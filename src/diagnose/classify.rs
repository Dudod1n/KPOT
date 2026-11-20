//! Hypotheses from observations: a pure function over the probes, one rule per table row.
use super::probes::{cdn, stub};
use super::{Confidence, Family, Kind, Outcome, Probe, Verdict};
use std::net::IpAddr;

/// Confidence grows when a sign repeats on the second attempt and the control stage is fine.
fn level(repeated: bool, control_ok: bool) -> Confidence {
    match (repeated, control_ok) {
        (true, true) => Confidence::High,
        (false, false) => Confidence::Low,
        _ => Confidence::Medium,
    }
}

fn verdict(
    code: &'static str,
    confidence: Confidence,
    evidence: Vec<usize>,
    hypothesis: &'static str,
    advice: &'static str,
) -> Verdict {
    Verdict {
        code,
        confidence,
        evidence,
        hypothesis,
        advice,
    }
}

fn indexes(probes: &[Probe], keep: impl Fn(&Probe) -> bool) -> Vec<usize> {
    probes
        .iter()
        .enumerate()
        .filter(|(_, p)| keep(p))
        .map(|(i, _)| i)
        .collect()
}

/// Whether every target among the evidence was tried at least twice, i.e. the sign repeated.
fn repeated(probes: &[Probe], evidence: &[usize]) -> bool {
    let target = |i: usize| (probes[i].kind, &probes[i].name, &probes[i].address);
    !evidence.is_empty()
        && evidence
            .iter()
            .all(|&i| evidence.iter().filter(|&&j| target(j) == target(i)).count() >= 2)
}

/// Builds hypotheses from the probes. It reads nothing but its argument.
pub fn classify(probes: &[Probe]) -> Vec<Verdict> {
    let ran = |p: &Probe| !p.outcome.is_skipped();
    let is = |p: &Probe, kind: Kind| p.kind == kind && ran(p);
    let control = indexes(probes, |p| {
        (p.kind == Kind::ControlDomestic || p.kind == Kind::ControlForeign) && ran(p)
    });
    let control_ok = control.iter().any(|&i| probes[i].outcome.is_ok());
    if !control.is_empty() && !control_ok {
        let all_timeout = control
            .iter()
            .all(|&i| probes[i].outcome == Outcome::Timeout);
        return vec![verdict(
            "no_network",
            if all_timeout && repeated(probes, &control) {
                Confidence::High
            } else {
                Confidence::Medium
            },
            control,
            "Нет доступа в интернет: не отвечает ни один контрольный узел.",
            "Проверьте подключение к сети; остальные этапы не оцениваются.",
        )];
    }
    let mut verdicts = Vec::new();

    let domestic_ok = probes
        .iter()
        .any(|p| is(p, Kind::ControlDomestic) && p.outcome.is_ok());
    let foreign = indexes(probes, |p| is(p, Kind::ControlForeign));
    if domestic_ok && !foreign.is_empty() && !foreign.iter().any(|&i| probes[i].outcome.is_ok()) {
        verdicts.push(verdict(
            "foreign_restricted",
            level(repeated(probes, &foreign), true),
            foreign,
            "Российские узлы доступны, зарубежные нет: белый список или ограничение зарубежного трафика.",
            "Проверьте из другой сети, например через мобильный интернет другого оператора.",
        ));
    }

    let system: Vec<IpAddr> = probes
        .iter()
        .filter(|p| is(p, Kind::DnsSystem) && p.outcome.is_ok())
        .flat_map(|p| p.answers.iter().filter_map(|a| a.parse().ok()))
        .collect();
    let mismatch = indexes(probes, |p| {
        p.kind == Kind::DnsCompare && p.outcome == Outcome::DnsMismatch
    });
    if !mismatch.is_empty() {
        let mut evidence = indexes(probes, |p| {
            (p.kind == Kind::DnsSystem || p.kind == Kind::DnsDoh) && ran(p)
        });
        evidence.extend(&mismatch);
        let clear = system.is_empty() || system.iter().any(stub);
        verdicts.push(verdict(
            "dns_spoofing",
            if clear {
                Confidence::High
            } else {
                Confidence::Low
            },
            evidence,
            "Системный DNS отвечает не так, как DoH: подмена или блокировка DNS.",
            "Укажите в туннеле IP-адрес сервера напрямую.",
        ));
    }

    let tcp_ssh = indexes(probes, |p| is(p, Kind::TcpSsh));
    let behind_cdn: Vec<usize> = tcp_ssh
        .iter()
        .copied()
        .filter(|&i| {
            probes[i]
                .address
                .as_deref()
                .and_then(|a| a.parse().ok())
                .is_some_and(|a: IpAddr| cdn(&a).is_some())
        })
        .collect();
    if !behind_cdn.is_empty() {
        verdicts.push(verdict(
            "cdn_address",
            Confidence::High,
            behind_cdn,
            "Адрес принадлежит CDN (Cloudflare), а CDN не проксирует SSH.",
            "Укажите прямой адрес сервера, а не имя за CDN.",
        ));
    }

    // Per address: the last attempt to the SSH port decides.
    let mut addresses: Vec<&str> = tcp_ssh
        .iter()
        .filter_map(|&i| probes[i].address.as_deref())
        .collect();
    addresses.dedup();
    let last = |address: &str| {
        tcp_ssh
            .iter()
            .rev()
            .map(|&i| &probes[i])
            .find(|p| p.address.as_deref() == Some(address))
            .map(|p| p.outcome.clone())
    };
    let closed = |address: &str| {
        probes
            .iter()
            .position(|p| is(p, Kind::TcpClosed) && p.address.as_deref() == Some(address))
    };
    let tested: Vec<&str> = addresses
        .iter()
        .copied()
        .filter(|a| last(a) != Some(Outcome::NoLocalRoute))
        .collect();
    let any_tcp_ok = tested.iter().any(|a| last(a) == Some(Outcome::Ok));
    if !any_tcp_ok && !tested.is_empty() {
        let evidence_of = |addresses: &[&str]| {
            let mut evidence = indexes(probes, |p| {
                (p.kind == Kind::TcpSsh || p.kind == Kind::TcpClosed)
                    && ran(p)
                    && p.address.as_deref().is_some_and(|a| addresses.contains(&a))
            });
            evidence.sort();
            evidence
        };
        let ssh_evidence = |addresses: &[&str]| {
            indexes(probes, |p| {
                is(p, Kind::TcpSsh) && p.address.as_deref().is_some_and(|a| addresses.contains(&a))
            })
        };
        let silent: Vec<&str> = tested
            .iter()
            .copied()
            .filter(|a| last(a) == Some(Outcome::Timeout))
            .collect();
        let closed_silent =
            |a: &&str| closed(a).is_some_and(|i| probes[i].outcome == Outcome::Timeout);
        let closed_answers =
            |a: &&str| closed(a).is_some_and(|i| probes[i].outcome == Outcome::Refused);
        if silent.len() == tested.len() && silent.iter().all(closed_silent) {
            let repeat = repeated(probes, &ssh_evidence(&silent));
            verdicts.push(verdict(
                "ip_blocked_or_down",
                level(repeat, control_ok).min(Confidence::Medium),
                evidence_of(&silent),
                "Адрес сервера не отвечает ни на порт SSH, ни на закрытый порт: блокировка IP или сервер недоступен.",
                "Сравните с другой сетью и проверьте, что сервер работает (консоль хостинга).",
            ));
        } else if silent.len() == tested.len() && silent.iter().any(closed_answers) {
            let answering: Vec<&str> = silent.iter().copied().filter(closed_answers).collect();
            verdicts.push(verdict(
                "port_filtered",
                level(repeated(probes, &ssh_evidence(&answering)), control_ok).min(Confidence::Medium),
                evidence_of(&answering),
                "IP отвечает, но порт SSH молчит: порт фильтруется на пути или межсетевым экраном сервера.",
                "Попробуйте другой порт SSH и проверьте правила межсетевого экрана сервера.",
            ));
        }
        let refused: Vec<&str> = tested
            .iter()
            .copied()
            .filter(|a| last(a) == Some(Outcome::Refused))
            .collect();
        if refused.len() == tested.len() {
            verdicts.push(verdict(
                "ssh_port_refused",
                level(true, control_ok),
                ssh_evidence(&refused),
                "Подключение к порту SSH отклонено: сервер не слушает этот порт или сброс приходит по пути.",
                "Проверьте номер порта и что sshd запущен.",
            ));
        }
    }

    let family_state = |family: Family| {
        let of_family: Vec<&str> = addresses
            .iter()
            .copied()
            .filter(|a| {
                a.parse::<IpAddr>()
                    .is_ok_and(|ip| Family::of(&ip) == family)
            })
            .collect();
        let ok = of_family.iter().any(|a| last(a) == Some(Outcome::Ok));
        let broken = !of_family.is_empty()
            && of_family
                .iter()
                .all(|a| matches!(last(a), Some(Outcome::Timeout | Outcome::Unreachable)));
        let no_route = !of_family.is_empty()
            && of_family
                .iter()
                .all(|a| last(a) == Some(Outcome::NoLocalRoute));
        (ok, broken, no_route, of_family)
    };
    let (v4_ok, v4_broken, v4_no_route, v4) = family_state(Family::V4);
    let (v6_ok, v6_broken, v6_no_route, v6) = family_state(Family::V6);
    for (ok, broken, other_ok, failed, hypothesis) in [
        (
            v4_ok,
            v6_broken,
            v4_ok,
            &v6,
            "IPv4 работает, IPv6 нет: блокировка или поломка IPv6 на пути.",
        ),
        (
            v6_ok,
            v4_broken,
            v6_ok,
            &v4,
            "IPv6 работает, IPv4 нет: блокировка или поломка IPv4 на пути.",
        ),
    ] {
        if ok && broken && other_ok {
            let evidence = indexes(probes, |p| {
                is(p, Kind::TcpSsh)
                    && p.address
                        .as_deref()
                        .is_some_and(|a| failed.contains(&a) || last(a) == Some(Outcome::Ok))
            });
            let failed_evidence = indexes(probes, |p| {
                is(p, Kind::TcpSsh) && p.address.as_deref().is_some_and(|a| failed.contains(&a))
            });
            verdicts.push(verdict(
                "address_family_broken",
                level(repeated(probes, &failed_evidence), control_ok),
                evidence,
                hypothesis,
                "Закрепите рабочее семейство адресов: укажите IP-адрес этого семейства вместо имени.",
            ));
        }
    }
    for (no_route, other_ok, family) in [(v6_no_route, v4_ok, &v6), (v4_no_route, v6_ok, &v4)] {
        if no_route && other_ok {
            verdicts.push(verdict(
                "no_local_route",
                Confidence::High,
                indexes(probes, |p| {
                    is(p, Kind::TcpSsh) && p.address.as_deref().is_some_and(|a| family.contains(&a))
                }),
                "В этой сети нет маршрута для одного из семейств адресов (обычно IPv6). Это не блокировка.",
                "Ничего делать не нужно: подключение идёт по другому семейству.",
            ));
        }
    }

    let handshakes = indexes(probes, |p| is(p, Kind::SshHandshake));
    let with = |outcomes: &[Outcome]| -> Vec<usize> {
        handshakes
            .iter()
            .copied()
            .filter(|&i| outcomes.contains(&probes[i].outcome))
            .collect()
    };
    let mismatch = with(&[Outcome::HostKeyMismatch]);
    let ssh_ok = with(&[Outcome::Ok]);
    let silent = with(&[Outcome::BannerMissing, Outcome::ResetAfterBanner]);
    let kex = with(&[Outcome::KexFailed]);
    if !mismatch.is_empty() {
        verdicts.push(verdict(
            "host_key_mismatch",
            Confidence::High,
            mismatch,
            "Ключ узла отличается от сохранённого: подмена сервера на пути или смена ключа на сервере.",
            "Не подключайтесь, пока не сверите отпечаток ключа по независимому каналу.",
        ));
    } else if !ssh_ok.is_empty() {
        verdicts.push(verdict(
            "reachable",
            Confidence::High,
            ssh_ok,
            "SSH-сервер доступен: обмен ключами завершён.",
            "Если туннель всё же не работает, проверьте учётные данные и настройки туннеля.",
        ));
    } else if !silent.is_empty() && kex.is_empty() {
        verdicts.push(verdict(
            "protocol_filtered",
            level(silent.len() >= 2, control_ok).min(Confidence::Medium),
            silent,
            "TCP открывается, но SSH обрывается до обмена ключами: фильтр протокола или порта либо защита сервера (fail2ban, MaxStartups).",
            "Попробуйте другой порт и проверьте журнал sshd и fail2ban на сервере.",
        ));
    } else if !kex.is_empty() {
        let repeat = kex.len() >= 2;
        verdicts.push(verdict(
            "ssh_signature_blocked",
            if repeat {
                level(true, control_ok)
            } else {
                Confidence::Low
            },
            kex,
            "Баннер проходит, но обмен ключами срывается: блокировка по сигнатуре SSH.",
            "Нужен транспорт-обёртка, скрывающий SSH (например, TLS).",
        ));
    }

    if verdicts.is_empty() {
        verdicts.push(verdict(
            "unknown",
            Confidence::Low,
            Vec::new(),
            "Явной причины не найдено.",
            "Повторите проверку позже и из другой сети.",
        ));
    }
    verdicts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(
        kind: Kind,
        name: &str,
        address: Option<&str>,
        outcome: Outcome,
        attempt: u8,
    ) -> Probe {
        let mut probe = Probe::new(kind, name);
        if let Some(address) = address {
            let ip: IpAddr = address.parse().unwrap();
            probe.family = Some(Family::of(&ip));
            probe.address = Some(address.into());
        }
        probe.outcome = outcome;
        probe.attempt = attempt;
        probe
    }
    fn control(outcome: Outcome) -> Vec<Probe> {
        let repeat = !outcome.is_ok();
        let mut out = vec![
            probe(Kind::ControlDomestic, "ya.ru", None, outcome.clone(), 1),
            probe(Kind::ControlForeign, "github.com", None, outcome.clone(), 1),
        ];
        if repeat {
            out.push(probe(
                Kind::ControlDomestic,
                "ya.ru",
                None,
                outcome.clone(),
                2,
            ));
            out.push(probe(Kind::ControlForeign, "github.com", None, outcome, 2));
        }
        out
    }
    fn tcp(address: &str, outcome: Outcome, attempt: u8) -> Probe {
        probe(Kind::TcpSsh, "порт SSH", Some(address), outcome, attempt)
    }
    fn closed(address: &str, outcome: Outcome) -> Probe {
        probe(Kind::TcpClosed, "закрытый порт", Some(address), outcome, 1)
    }
    fn ssh(outcome: Outcome, attempt: u8) -> Probe {
        probe(
            Kind::SshHandshake,
            "обмен ключами",
            Some("192.0.2.1"),
            outcome,
            attempt,
        )
    }
    fn codes(probes: &[Probe]) -> Vec<(&'static str, Confidence)> {
        classify(probes)
            .iter()
            .map(|v| (v.code, v.confidence))
            .collect()
    }
    fn find(probes: &[Probe], code: &str) -> Verdict {
        classify(probes)
            .into_iter()
            .find(|v| v.code == code)
            .unwrap_or_else(|| panic!("{code} missing: {:?}", codes(probes)))
    }

    #[test]
    fn no_network_stops_the_evaluation() {
        let mut probes = control(Outcome::Timeout);
        probes.push(tcp("192.0.2.1", Outcome::Timeout, 1));
        assert_eq!(codes(&probes), [("no_network", Confidence::High)]);
        assert_eq!(classify(&probes)[0].evidence, [0, 1, 2, 3]);
    }

    #[test]
    fn domestic_only_means_whitelist() {
        let mut probes = vec![
            probe(Kind::ControlDomestic, "ya.ru", None, Outcome::Ok, 1),
            probe(
                Kind::ControlForeign,
                "github.com",
                None,
                Outcome::Timeout,
                1,
            ),
            probe(
                Kind::ControlForeign,
                "github.com",
                None,
                Outcome::Timeout,
                2,
            ),
        ];
        probes.push(tcp("192.0.2.1", Outcome::Ok, 1));
        let found = find(&probes, "foreign_restricted");
        assert_eq!(found.confidence, Confidence::High);
        assert_eq!(found.evidence, [1, 2]);
    }

    #[test]
    fn dns_mismatch_with_stub_is_spoofing() {
        let mut probes = control(Outcome::Ok);
        let mut system = probe(Kind::DnsSystem, "system", None, Outcome::Ok, 1);
        system.answers = vec!["10.10.10.10".into()];
        let mut doh = probe(Kind::DnsDoh, "cloudflare", None, Outcome::Ok, 1);
        doh.answers = vec!["192.0.2.1".into()];
        probes.extend([
            system,
            doh,
            probe(Kind::DnsCompare, "cmp", None, Outcome::DnsMismatch, 1),
        ]);
        assert_eq!(find(&probes, "dns_spoofing").confidence, Confidence::High);
        // Disjoint public answers may be a CDN: only a weak sign.
        probes[2].answers = vec!["198.51.100.1".into()];
        assert_eq!(find(&probes, "dns_spoofing").confidence, Confidence::Low);
        // A DoH failure is unknown, not evidence.
        probes[4].outcome = Outcome::Skipped("нет ответа DoH".into());
        assert!(classify(&probes).iter().all(|v| v.code != "dns_spoofing"));
    }

    #[test]
    fn cdn_address_cannot_carry_ssh() {
        let mut probes = control(Outcome::Ok);
        probes.push(tcp("104.16.0.1", Outcome::Ok, 1));
        probes.push(ssh(Outcome::BannerMissing, 1));
        assert_eq!(find(&probes, "cdn_address").evidence, [2]);
    }

    #[test]
    fn silent_ssh_and_closed_ports_mean_ip_block_or_down_server() {
        let mut probes = control(Outcome::Ok);
        probes.extend([
            tcp("192.0.2.1", Outcome::Timeout, 1),
            tcp("192.0.2.1", Outcome::Timeout, 2),
            closed("192.0.2.1", Outcome::Timeout),
            ssh(Outcome::Skipped("нет TCP".into()), 1),
        ]);
        let found = find(&probes, "ip_blocked_or_down");
        // Two explanations at once: never more than medium.
        assert_eq!(found.confidence, Confidence::Medium);
        assert_eq!(found.evidence, [2, 3, 4]);
        probes[4].outcome = Outcome::Refused;
        assert_eq!(find(&probes, "port_filtered").evidence, [2, 3, 4]);
        assert!(
            classify(&probes)
                .iter()
                .all(|v| v.code != "ip_blocked_or_down")
        );
    }

    #[test]
    fn refused_ssh_port() {
        let mut probes = control(Outcome::Ok);
        probes.extend([
            tcp("192.0.2.1", Outcome::Refused, 1),
            closed("192.0.2.1", Outcome::Refused),
        ]);
        assert_eq!(
            find(&probes, "ssh_port_refused").confidence,
            Confidence::High
        );
    }

    #[test]
    fn tcp_ok_without_banner_is_a_protocol_filter_or_server_protection() {
        let mut probes = control(Outcome::Ok);
        probes.extend([
            tcp("192.0.2.1", Outcome::Ok, 1),
            ssh(Outcome::BannerMissing, 1),
            ssh(Outcome::ResetAfterBanner, 2),
        ]);
        let found = find(&probes, "protocol_filtered");
        assert_eq!(found.confidence, Confidence::Medium);
        assert_eq!(found.evidence, [3, 4]);
    }

    #[test]
    fn repeated_kex_failure_is_a_signature_block() {
        let mut probes = control(Outcome::Ok);
        probes.extend([tcp("192.0.2.1", Outcome::Ok, 1), ssh(Outcome::KexFailed, 1)]);
        assert_eq!(
            find(&probes, "ssh_signature_blocked").confidence,
            Confidence::Low
        );
        probes.push(ssh(Outcome::KexFailed, 2));
        assert_eq!(
            find(&probes, "ssh_signature_blocked").confidence,
            Confidence::High
        );
    }

    #[test]
    fn one_family_works_and_the_other_times_out() {
        let mut probes = control(Outcome::Ok);
        probes.extend([
            tcp("192.0.2.1", Outcome::Ok, 1),
            tcp("2001:db8::1", Outcome::Timeout, 1),
            tcp("2001:db8::1", Outcome::Timeout, 2),
            closed("2001:db8::1", Outcome::Timeout),
            ssh(Outcome::Ok, 1),
        ]);
        let found = find(&probes, "address_family_broken");
        assert_eq!(found.confidence, Confidence::High);
        assert_eq!(found.evidence, [2, 3, 4]);
        assert!(
            classify(&probes)
                .iter()
                .all(|v| v.code != "ip_blocked_or_down")
        );
    }

    #[test]
    fn missing_local_ipv6_is_not_a_block() {
        let mut probes = control(Outcome::Ok);
        probes.extend([
            tcp("192.0.2.1", Outcome::Ok, 1),
            tcp("2001:db8::1", Outcome::NoLocalRoute, 1),
            ssh(Outcome::Ok, 1),
        ]);
        let found = codes(&probes);
        assert!(
            found.contains(&("no_local_route", Confidence::High)),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .all(|(code, _)| *code != "address_family_broken")
        );
    }

    #[test]
    fn changed_host_key_wins_over_reachability() {
        let mut probes = control(Outcome::Ok);
        probes.extend([
            tcp("192.0.2.1", Outcome::Ok, 1),
            ssh(Outcome::HostKeyMismatch, 1),
        ]);
        assert_eq!(codes(&probes), [("host_key_mismatch", Confidence::High)]);
    }

    #[test]
    fn a_clean_run_is_reachable_and_an_empty_one_unknown() {
        let mut probes = control(Outcome::Ok);
        probes.extend([tcp("192.0.2.1", Outcome::Ok, 1), ssh(Outcome::Ok, 1)]);
        assert_eq!(codes(&probes), [("reachable", Confidence::High)]);
        assert_eq!(codes(&[]), [("unknown", Confidence::Low)]);
    }

    #[test]
    fn without_control_confidence_stays_lower() {
        let probes = vec![
            tcp("192.0.2.1", Outcome::Timeout, 1),
            closed("192.0.2.1", Outcome::Timeout),
        ];
        assert_eq!(
            find(&probes, "ip_blocked_or_down").confidence,
            Confidence::Low
        );
    }
}
