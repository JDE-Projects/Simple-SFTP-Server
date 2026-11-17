"""Window restore failures are recorded without changing restore behavior."""

from types import SimpleNamespace

from app.debug_log import describe_error
from app.services import prefs


GEO = {"x": 100, "y": 100, "width": 1200, "height": 800}


class _Call:
    def __init__(self, result=0, effect=None):
        self.result = result
        self.effect = effect
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        if self.effect is not None:
            return self.effect(*args)
        return self.result


class _WindowApi:
    def __init__(self, get_rect_result=1):
        self.SetWindowPos = _Call(1)

        def get_window_rect(_hwnd, rect):
            if get_rect_result:
                current = rect._obj
                current.left, current.top = GEO["x"], GEO["y"]
                current.right = GEO["x"] + GEO["width"]
                current.bottom = GEO["y"] + GEO["height"]
            return get_rect_result

        self.GetWindowRect = _Call(effect=get_window_rect)


def _logs(monkeypatch):
    recorded = []
    monkeypatch.setattr(prefs.debug, "_log", lambda label, content="": recorded.append((label, content)))
    return recorded


def _patch_restore(monkeypatch, *, point_monitor=1, window_monitor=1, work_area=(0, 0, 1920, 1080),
                   window_api=None, hwnd=1):
    user32 = SimpleNamespace(
        MonitorFromPoint=_Call(point_monitor),
        MonitorFromWindow=_Call(window_monitor),
    )
    monkeypatch.setattr(prefs.ctypes, "windll", SimpleNamespace(user32=user32))
    monkeypatch.setattr(prefs, "_monitor_work_area", lambda _monitor: work_area)
    monkeypatch.setattr(prefs, "_own_window_handle", lambda _title: hwnd)
    monkeypatch.setattr(prefs, "_win32", lambda: window_api or _WindowApi())
    monkeypatch.setattr(prefs, "_frame_insets", lambda _hwnd: (0, 0, 0, 0))
    monkeypatch.setattr(prefs.time, "sleep", lambda _seconds: None)
    return user32


def test_no_monitor_logs_and_keeps_default_spot(monkeypatch):
    logs = _logs(monkeypatch)
    window_api = _WindowApi()
    _patch_restore(monkeypatch, point_monitor=0, window_api=window_api)

    prefs._apply_window_rect(GEO)

    assert logs == [("window restore: saved spot not on any monitor, kept default spot", "")]
    assert window_api.SetWindowPos.calls == []


def test_first_work_area_failure_logs(monkeypatch):
    logs = _logs(monkeypatch)
    _patch_restore(monkeypatch, work_area=None)

    prefs._apply_window_rect(GEO)

    assert logs == [("window restore: monitor work area not read (first pass)", "")]


def test_missing_window_handle_logs(monkeypatch):
    logs = _logs(monkeypatch)
    _patch_restore(monkeypatch, hwnd=None)

    prefs._apply_window_rect(GEO)

    assert logs == [("window restore: app window not found", "")]


def test_unreadable_window_size_after_move_logs(monkeypatch):
    logs = _logs(monkeypatch)
    window_api = _WindowApi(get_rect_result=0)
    _patch_restore(monkeypatch, window_api=window_api)

    prefs._apply_window_rect(GEO)

    assert logs == [("window restore: window size not read after move", "")]
    assert len(window_api.SetWindowPos.calls) == 1


def test_missing_monitor_for_second_fit_logs(monkeypatch):
    logs = _logs(monkeypatch)
    _patch_restore(monkeypatch, window_monitor=0)

    prefs._apply_window_rect(GEO)

    assert logs == [("window restore: monitor not found for second fit", "")]


def test_second_work_area_failure_logs(monkeypatch):
    logs = _logs(monkeypatch)
    work_areas = iter(((0, 0, 1920, 1080), None))
    _patch_restore(monkeypatch)
    monkeypatch.setattr(prefs, "_monitor_work_area", lambda _monitor: next(work_areas))

    prefs._apply_window_rect(GEO)

    assert logs == [("window restore: monitor work area not read (second pass)", "")]


def test_restore_exception_is_logged_without_escaping(monkeypatch):
    logs = _logs(monkeypatch)
    error = OSError(5, "hidden detail")
    user32 = _patch_restore(monkeypatch)
    user32.MonitorFromPoint = _Call(effect=lambda *_args: (_ for _ in ()).throw(error))

    prefs._apply_window_rect(GEO)

    assert logs == [("window restore: failed", describe_error(error))]


def test_success_path_does_not_log(monkeypatch):
    logs = _logs(monkeypatch)
    _patch_restore(monkeypatch)

    prefs._apply_window_rect(GEO)

    assert logs == []


def test_unreadable_saved_size_logs_and_returns_empty(monkeypatch):
    logs = _logs(monkeypatch)
    error = OSError(5, "hidden detail")
    monkeypatch.setattr(prefs, "load_prefs", lambda: (_ for _ in ()).throw(error))

    assert prefs._restore_geometry() == {}
    assert logs == [("window restore: saved size not read", describe_error(error))]


def test_unusable_saved_size_logs_and_returns_empty(monkeypatch):
    logs = _logs(monkeypatch)
    monkeypatch.setattr(prefs, "load_prefs", lambda: {"window": "junk"})

    assert prefs._restore_geometry() == {}
    assert logs == [("window restore: saved size unusable, using default", "")]


def test_missing_saved_size_returns_empty_without_logging(monkeypatch):
    logs = _logs(monkeypatch)
    monkeypatch.setattr(prefs, "load_prefs", lambda: {})

    assert prefs._restore_geometry() == {}
    assert logs == []


def test_valid_saved_size_returns_without_logging(monkeypatch):
    logs = _logs(monkeypatch)
    monkeypatch.setattr(prefs, "load_prefs", lambda: {"window": GEO})

    assert prefs._restore_geometry() == GEO
    assert logs == []


def test_window_restore_labels_are_distinct():
    labels = [
        "window restore: saved spot not on any monitor, kept default spot",
        "window restore: monitor work area not read (first pass)",
        "window restore: app window not found",
        "window restore: window size not read after move",
        "window restore: monitor not found for second fit",
        "window restore: monitor work area not read (second pass)",
        "window restore: failed",
        "window restore: saved size not read",
        "window restore: saved size unusable, using default",
    ]

    assert len(labels) == len(set(labels)) == 9
