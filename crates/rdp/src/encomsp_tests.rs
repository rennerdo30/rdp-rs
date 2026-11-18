use super::*;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

fn one(bytes: &str) -> Order {
    let mut v = parse(&hex(bytes)).unwrap();
    assert_eq!(v.len(), 1);
    v.remove(0)
}

const ME_JOINED: &str = "08 00 24 00 00 00 00 00 00 00 00 00 04 00 0A 00 \
     54 00 45 00 53 00 54 00 55 00 53 00 45 00 52 00 30 00 32 00";
const ME_VIEW: &str = "08 00 24 00 00 00 00 00 00 00 00 00 01 00 0A 00 \
     54 00 45 00 53 00 54 00 55 00 53 00 45 00 52 00 30 00 32 00";

#[test]
fn filter_updated_spec_examples() {
    // MS-RDPEMC 4.1.1 and 4.1.4.
    assert_eq!(
        one("01 00 05 00 00"),
        Order::FilterUpdated { enabled: false }
    );
    assert_eq!(
        one("01 00 05 00 01"),
        Order::FilterUpdated { enabled: true }
    );
}

#[test]
fn participant_created_spec_examples() {
    // MS-RDPEMC 4.1.2: to the new participant (IS_PARTICIPANT), to the
    // others (no flags), and a control level change (MAY_VIEW).
    for (bytes, flags) in [(ME_JOINED, IS_PARTICIPANT), (ME_VIEW, MAY_VIEW)] {
        assert_eq!(
            one(bytes),
            Order::ParticipantCreated {
                id: 0,
                group_id: 0,
                flags,
                name: "TESTUSER02".into()
            }
        );
    }
    let others = "08 00 24 00 00 00 00 00 00 00 00 00 00 00 0A 00 \
         54 00 45 00 53 00 54 00 55 00 53 00 45 00 52 00 30 00 32 00";
    assert!(matches!(
        one(others),
        Order::ParticipantCreated { flags: 0, .. }
    ));
}

#[test]
fn participant_removed_spec_example() {
    // MS-RDPEMC 4.1.3: could not send data to the participant.
    assert_eq!(
        one("07 00 10 00 00 00 00 00 00 00 00 00 06 00 0A D0"),
        Order::ParticipantRemoved {
            id: 0,
            disc_type: 0,
            disc_code: 0xD00A_0006
        }
    );
}

#[test]
fn application_and_window_spec_examples() {
    // MS-RDPEMC 4.1.5 to 4.1.8 and 4.1.10.
    assert_eq!(
        one("03 00 14 00 01 00 EC 0A 00 00 04 00 63 00 61 00 6C 00 63 00"),
        Order::AppCreated {
            flags: SHARED,
            app_id: 2796,
            name: "calc".into()
        }
    );
    assert_eq!(
        one("02 00 08 00 90 0C 00 00"),
        Order::AppRemoved { app_id: 3216 }
    );
    assert_eq!(
        one("05 00 24 00 00 00 EC 0A 00 00 96 03 1C 00 0A 00 \
             43 00 61 00 6C 00 63 00 75 00 6C 00 61 00 74 00 6F 00 72 00"),
        Order::WndCreated {
            flags: 0,
            app_id: 2796,
            wnd_id: 1_835_926,
            name: "Calculator".into()
        }
    );
    assert_eq!(
        one("04 00 08 00 96 03 1C 00"),
        Order::WndRemoved { wnd_id: 1_835_926 }
    );
    assert_eq!(
        one("0C 00 14 00 31 01 00 00 5B 00 00 00 D3 02 00 00 BD 02 00 00"),
        Order::WndRegionUpdate {
            left: 305,
            top: 91,
            right: 723,
            bottom: 701
        }
    );
}

#[test]
fn control_response_spec_example() {
    // MS-RDPEMC 4.1.9. The spec annotates ParticipantId as 1, but its bytes
    // `00 00 00 01` are 0x01000000 little-endian like every other field.
    assert_eq!(
        one("0D 00 0E 00 03 00 00 00 00 01 00 00 00 00"),
        Order::CtrlChangeResponse {
            flags: REQUEST_VIEW | REQUEST_INTERACT,
            id: 0x0100_0000,
            reason: 0
        }
    );
}

#[test]
fn participant_orders_match_spec_bytes() {
    // MS-RDPEMC 4.2.1 (view and interact for participant 0) and 4.2.2.
    assert_eq!(
        ctrl_change(REQUEST_VIEW | REQUEST_INTERACT, 0),
        hex("09 00 0A 00 03 00 00 00 00 00")
    );
    assert_eq!(wnd_show(1_835_926), hex("06 00 08 00 96 03 1C 00"));
    assert_eq!(
        parse(&wnd_show(7)).unwrap(),
        vec![Order::WndShow { wnd_id: 7 }]
    );
}

#[test]
fn several_orders_and_unknown_types_in_one_message() {
    // 3.1.5.1: orders are concatenated; an unknown type is skipped.
    let msg = hex("0A 00 04 00 77 00 06 00 AA BB 0B 00 04 00");
    assert_eq!(
        parse(&msg).unwrap(),
        vec![Order::StreamPaused, Order::StreamResumed]
    );
}

#[test]
fn malformed_orders_are_errors() {
    for bad in [
        "01 00 03 00",             // Length below the header size
        "01 00 06 00 00",          // Length past the message
        "07 00 08 00 00 00 00 00", // Participant-Removed without DiscType/Code
        "01 00",                   // truncated header
        // cchString 10 with only 2 characters of data
        "08 00 12 00 00 00 00 00 00 00 00 00 01 00 0A 00 41 00",
        // cchString 1025 (max 1024)
        "08 00 10 00 00 00 00 00 00 00 00 00 01 00 01 04",
    ] {
        assert!(parse(&hex(bad)).is_err(), "{bad}");
    }
}

#[test]
fn name_is_optional_and_stops_at_a_null() {
    // Windows treats Name as optional (MS-RDPEMC 6 <10>).
    assert_eq!(
        one("03 00 0A 00 00 00 01 00 00 00"),
        Order::AppCreated {
            flags: 0,
            app_id: 1,
            name: String::new()
        }
    );
    // cchString counts characters; the string ends at the first null (2.2.2).
    assert_eq!(
        one("03 00 12 00 00 00 01 00 00 00 03 00 41 00 00 00 42 00"),
        Order::AppCreated {
            flags: 0,
            app_id: 1,
            name: "A".into()
        }
    );
}

#[test]
fn control_level_follows_my_participant_record() {
    let mut s = MultipartyState::default();
    // Joined with no rights yet: known as "me", nothing to show.
    assert_eq!(s.apply(one(ME_JOINED)), None);
    assert_eq!(s.me, Some(0));
    assert_eq!(s.control(), Control::None);
    // The control level change carries no IS_PARTICIPANT; it is "me" by id.
    assert_eq!(
        s.apply(one(ME_VIEW)),
        Some(MultipartyEvent::ControlChanged(Control::View))
    );
    assert_eq!(s.apply(one(ME_VIEW)), None, "no change, no event");
    let interact = Order::ParticipantCreated {
        id: 0,
        group_id: 0,
        flags: MAY_VIEW | MAY_INTERACT,
        name: "TESTUSER02".into(),
    };
    assert_eq!(
        s.apply(interact),
        Some(MultipartyEvent::ControlChanged(Control::Interact))
    );
    assert_eq!(s.control(), Control::Interact);
}

#[test]
fn other_participants_join_once_and_leave() {
    let mut s = MultipartyState::default();
    s.apply(one(ME_JOINED));
    let admin = Order::ParticipantCreated {
        id: 5,
        group_id: 0,
        flags: MAY_VIEW,
        name: "admin".into(),
    };
    assert_eq!(
        s.apply(admin.clone()),
        Some(MultipartyEvent::Joined {
            id: 5,
            name: "admin".into()
        })
    );
    assert_eq!(s.apply(admin), None, "an update is not a second join");
    assert_eq!(s.control(), Control::None, "another's rights are not mine");
    assert_eq!(
        s.apply(Order::ParticipantRemoved {
            id: 5,
            disc_type: 2,
            disc_code: 0
        }),
        Some(MultipartyEvent::Left {
            id: 5,
            name: "admin".into(),
            code: 0
        })
    );
    assert_eq!(
        s.apply(Order::ParticipantRemoved {
            id: 5,
            disc_type: 2,
            disc_code: 0
        }),
        None,
        "an unknown participant is ignored (3.1.5.3)"
    );
}

#[test]
fn pause_and_resume_report_changes_only() {
    let mut s = MultipartyState::default();
    assert_eq!(s.apply(Order::StreamResumed), None);
    assert_eq!(
        s.apply(Order::StreamPaused),
        Some(MultipartyEvent::Paused(true))
    );
    assert_eq!(s.apply(Order::StreamPaused), None);
    assert!(s.paused);
    assert_eq!(
        s.apply(Order::StreamResumed),
        Some(MultipartyEvent::Paused(false))
    );
}

#[test]
fn removing_an_application_removes_its_windows_and_filter_resets_lists() {
    let mut s = MultipartyState::default();
    for (app, wnd) in [(1, 10), (1, 11), (2, 20)] {
        s.apply(Order::AppCreated {
            flags: SHARED,
            app_id: app,
            name: format!("app{app}"),
        });
        s.apply(Order::WndCreated {
            flags: SHARED,
            app_id: app,
            wnd_id: wnd,
            name: format!("w{wnd}"),
        });
    }
    s.apply(Order::AppRemoved { app_id: 1 });
    assert_eq!(s.windows.keys().copied().collect::<Vec<_>>(), vec![20]);
    s.apply(Order::FilterUpdated { enabled: true });
    assert!(s.filter_enabled && s.apps.is_empty() && s.windows.is_empty());
}

#[test]
fn channel_reports_events_and_sends_control_requests() {
    let (mut ch, handle) = multiparty();
    assert_eq!(ch.name(), "encomsp");
    let mut out = ChannelOut::default();
    let mut msg = hex(ME_JOINED);
    msg.extend(hex(ME_VIEW));
    ch.process(&msg, &mut out).unwrap();
    assert!(out.is_empty());
    assert_eq!(
        handle.take_events(),
        vec![MultipartyEvent::ControlChanged(Control::View)]
    );
    assert!(handle.take_events().is_empty());
    assert_eq!(handle.control(), Control::View);

    handle.request_control(true);
    ch.tick(&mut out).unwrap();
    assert_eq!(
        out.take(),
        vec![ctrl_change(REQUEST_VIEW | REQUEST_INTERACT, 0)]
    );
    handle.request_control(false);
    handle.show_window(9);
    ch.tick(&mut out).unwrap();
    assert_eq!(out.take(), vec![ctrl_change(REQUEST_VIEW, 0), wnd_show(9)]);

    // A malformed message is an error (the client disables the channel).
    assert!(ch.process(&hex("08 00 30 00"), &mut out).is_err());
    assert_eq!(handle.control(), Control::View, "state kept");
}
