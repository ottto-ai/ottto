//! Owns the ordered, test-only effect sink used by pipeline oracle receipts.
//! Each recording restores its thread's previous sink; workers enter explicitly.
//! No sink means no effect, and receipts use the crate's canonical JSON bytes.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub(crate) enum Scalar {
    U64(u64),
    Bool(bool),
    Text(String),
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Effect {
    pub(crate) label: &'static str,
    pub(crate) fields: Vec<(&'static str, Scalar)>,
}

type Sink = Arc<Mutex<Vec<Effect>>>;
thread_local! { static CURRENT: RefCell<Option<Sink>> = const { RefCell::new(None) }; }

#[derive(Clone)]
pub(crate) struct Handle(Sink);

// Restoring a thread-local sink must happen on the thread that installed it.
pub(crate) struct Enter(Option<Sink>, PhantomData<Rc<()>>);
impl Drop for Enter {
    fn drop(&mut self) {
        CURRENT.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}
impl Handle {
    pub(crate) fn enter(&self) -> Enter {
        Enter(
            CURRENT.with(|slot| slot.replace(Some(self.0.clone()))),
            PhantomData,
        )
    }
}

pub(crate) struct Recording {
    handle: Handle,
    _entered: Enter,
}
impl Recording {
    pub(crate) fn start() -> Self {
        let handle = Handle(Arc::new(Mutex::new(Vec::new())));
        let entered = handle.enter();
        Self {
            handle,
            _entered: entered,
        }
    }
    pub(crate) fn handle(&self) -> Handle {
        self.handle.clone()
    }
    pub(crate) fn take(&self) -> Vec<Effect> {
        std::mem::take(&mut *self.handle.0.lock().unwrap())
    }
}

pub(crate) fn record(label: &'static str, fields: Vec<(&'static str, Scalar)>) {
    CURRENT.with(|slot| {
        if let Some(sink) = slot.borrow().as_ref() {
            sink.lock().unwrap().push(Effect { label, fields });
        }
    });
}

pub(crate) fn canonical(effects: &[Effect]) -> Vec<u8> {
    crate::canonical_json::canonicalize(&serde_json::to_value(effects).unwrap()).unwrap()
}

#[test]
fn order_and_canonical_scalars() {
    use Scalar::{Bool, Text, U64};
    let recording = Recording::start();
    record("first", vec![("n", U64(2)), ("ok", Bool(true))]);
    record("second", vec![("state", Text("saved".into()))]);
    assert_eq!(canonical(&recording.take()), br#"[{"fields":[["n",2],["ok",true]],"label":"first"},{"fields":[["state","saved"]],"label":"second"}]"#);
    assert!(recording.take().is_empty());
}

#[test]
fn cross_thread_enter() {
    let recording = Recording::start();
    let handle = recording.handle();
    std::thread::spawn(move || {
        record("outside", vec![]);
        let entered = handle.enter();
        record("worker", vec![]);
        drop(entered);
        record("after", vec![]);
    })
    .join()
    .unwrap();
    assert_eq!(
        canonical(&recording.take()),
        br#"[{"fields":[],"label":"worker"}]"#
    );
}

#[test]
fn absent_sink_is_noop() {
    assert!(CURRENT.with(|slot| slot.borrow().is_none()));
    record("ignored", vec![("n", Scalar::U64(1))]);
    let recording = Recording::start();
    assert!(recording.take().is_empty());
    drop(recording);
    assert!(CURRENT.with(|slot| slot.borrow().is_none()));
}

#[test]
fn nested_recording_restores_on_unwind() {
    let outer = Recording::start();
    record("before", vec![]);
    let panic = std::panic::catch_unwind(|| {
        let inner = Recording::start();
        record("inner", vec![]);
        assert_eq!(inner.take()[0].label, "inner");
        panic!("synthetic unwind");
    });
    assert!(panic.is_err());
    record("after", vec![]);
    assert_eq!(
        outer.take().iter().map(|e| e.label).collect::<Vec<_>>(),
        ["before", "after"]
    );
}
