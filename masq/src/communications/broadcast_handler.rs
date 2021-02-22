// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::commands::change_password_command::ChangePasswordCommand;
use crate::commands::setup_command::SetupCommand;
use crate::communications::handle_node_not_running_for_fire_and_forget;
use crate::notifications::crashed_notification::CrashNotifier;
use crossbeam_channel::{unbounded, Receiver, RecvError, Sender};
use masq_lib::messages::{
    FromMessageBody, UiNewPasswordBroadcast, UiNodeCrashedBroadcast, UiSetupBroadcast,
    UiUndeliveredFireAndForget,
};
use masq_lib::ui_gateway::MessageBody;
use std::fmt::Debug;
use std::io::Write;
use std::thread;
use std::sync::{Mutex, Arc};

pub trait BroadcastHandle: Send {
    fn send(&self, message_body: MessageBody);
}

pub struct BroadcastHandleGeneric {
    message_tx: Sender<MessageBody>,
}

impl BroadcastHandle for BroadcastHandleGeneric {
    fn send(&self, message_body: MessageBody) {
        self.message_tx
            .send(message_body)
            .expect("Message send failed")
    }
}

pub trait BroadcastHandler {
    fn start(self, stream_factory: Box<dyn StreamFactory>) -> Box<dyn BroadcastHandle>;
}

pub struct BroadcastHandlerReal {
    output_synchronizer: Arc<Mutex<()>>
}

impl BroadcastHandler for BroadcastHandlerReal {
    fn start(self, stream_factory: Box<dyn StreamFactory>) -> Box<dyn BroadcastHandle> {
        let (message_tx, message_rx) = unbounded();
        thread::spawn(move || {
            let (mut stdout, mut stderr) = stream_factory.make();
            loop {
                Self::thread_loop_guts(&message_rx, &self.output_synchronizer, stdout.as_mut(), stderr.as_mut())
            }
        });
        Box::new(BroadcastHandleGeneric { message_tx })
    }
}

impl BroadcastHandlerReal {
    pub fn new(output_synchronizer: Arc<Mutex<()>>) -> Self {
        Self {output_synchronizer}
    }

    fn handle_message_body(
        message_body_result: Result<MessageBody, RecvError>,
        output_synchronizer: &Arc<Mutex<()>>,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) {
        match message_body_result {
            Err(_) => (), // Receiver died; masq is going down
            Ok(message_body) => {
                let _sync = output_synchronizer.lock().expect ("CommandProcessor is dead");
                if let Ok((body, _)) = UiSetupBroadcast::fmb(message_body.clone()) {
                    SetupCommand::handle_broadcast(body, stdout);
                } else if let Ok((body, _)) = UiNodeCrashedBroadcast::fmb(message_body.clone()) {
                    CrashNotifier::handle_broadcast(body, stdout);
                } else if let Ok((_, _)) = UiNewPasswordBroadcast::fmb(message_body.clone()) {
                    ChangePasswordCommand::handle_broadcast(stdout);
                } else if let Ok((body, _)) = UiUndeliveredFireAndForget::fmb(message_body.clone()) {
                    handle_node_not_running_for_fire_and_forget(body, stdout);
                } else {
                    write!(
                        stderr,
                        "Discarding unrecognized broadcast with opcode '{}'\n\nmasq> ",
                        message_body.opcode
                    )
                    .expect("write! failed");
                }
            }
        }
    }

    fn thread_loop_guts(
        message_rx: &Receiver<MessageBody>,
        output_synchronizer: &Arc<Mutex<()>>,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) {
        select! {
            recv(message_rx) -> message_body_result => Self::handle_message_body (message_body_result,
                output_synchronizer, stdout, stderr),
        }
    }
}

pub trait StreamFactory: Send + Debug {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>);
}

#[derive(Clone, PartialEq, Debug)]
pub struct StreamFactoryReal {}

impl StreamFactory for StreamFactoryReal {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>) {
        (Box::new(std::io::stdout()), Box::new(std::io::stderr()))
    }
}

impl Default for StreamFactoryReal {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::TestStreamFactory;
    use masq_lib::messages::UiSetupBroadcast;
    use masq_lib::messages::{CrashReason, ToMessageBody, UiNodeCrashedBroadcast};
    use masq_lib::ui_gateway::MessagePath;

    #[test]
    fn broadcast_of_setup_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Arc::new(Mutex::new(())))
            .start(Box::new(factory));
        let message = UiSetupBroadcast {
            running: true,
            values: vec![],
            errors: vec![],
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout.contains("the Node is currently running"),
            true,
            "stdout: '{}' doesn't contain 'the Node is currently running'",
            stdout
        );
        assert_eq!(
            stdout.contains("masq> "),
            true,
            "stdout: '{}' doesn't contain 'masq> '",
            stdout
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn broadcast_of_crashed_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Arc::new(Mutex::new(())))
            .start(Box::new(factory));
        let message = UiNodeCrashedBroadcast {
            process_id: 1234,
            crash_reason: CrashReason::Unrecognized("Unknown crash reason".to_string()),
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nThe Node running as process 1234 terminated:\n------\nUnknown crash reason\n------\nThe Daemon is once more accepting setup changes.\n\nmasq> ".to_string()
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn broadcast_of_new_password_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Arc::new(Mutex::new(())))
            .start(Box::new(factory));
        let message = UiNewPasswordBroadcast {}.tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nThe Node's database password has changed.\n\nmasq> ".to_string()
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn broadcast_of_undelivered_ff_message_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Arc::new(Mutex::new(())))
            .start(Box::new(factory));
        let message = UiUndeliveredFireAndForget {
            opcode: "uninventedMessage".to_string(),
            original_payload: "This must be said to the Node immediately!".to_string(),
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nCannot handle uninventedMessage request: Node is not running\nmasq> "
                .to_string()
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn unexpected_broadcasts_are_ineffectual_but_dont_kill_the_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Arc::new(Mutex::new(())))
            .start(Box::new(factory));
        let bad_message = MessageBody {
            opcode: "unrecognized".to_string(),
            path: MessagePath::FireAndForget,
            payload: (Ok("".to_string())),
        };
        let good_message = UiSetupBroadcast {
            running: true,
            values: vec![],
            errors: vec![],
        }
        .tmb(0);

        subject.send(bad_message);

        assert_eq!(handle.stdout_so_far(), String::new());
        assert_eq!(
            handle.stderr_so_far(),
            ("Discarding unrecognized broadcast with opcode 'unrecognized'\n\nmasq> ")
        );

        subject.send(good_message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout.contains("the Node is currently running"),
            true,
            "stdout: '{}' doesn't contain 'the Node is currently running'",
            stdout
        );
        assert_eq!(handle.stderr_so_far(), String::new());
    }
}
