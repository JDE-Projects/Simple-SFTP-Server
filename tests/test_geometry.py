"""Tests for the pure window-geometry helpers in app/services/prefs.py:
_valid_geometry (validation of a saved geometry dict) and
fit_rect_to_work_area (the fitting math behind _apply_window_rect). The Win32
calls around them need a live desktop window and are covered by the
window-fit UI checks in tools/ui_check instead."""

from app.services.prefs import _valid_geometry, fit_rect_to_work_area


def test_valid_dict_passes_through_unchanged():
    geo = {"x": 100, "y": 80, "width": 1200, "height": 800}
    assert _valid_geometry(geo) == {"x": 100, "y": 80, "width": 1200, "height": 800}


def test_not_a_dict_returns_empty():
    assert _valid_geometry(None) == {}
    assert _valid_geometry("nope") == {}
    assert _valid_geometry([1, 2, 3]) == {}


def test_missing_key_returns_empty():
    assert _valid_geometry({"x": 0, "y": 0, "width": 1000}) == {}
    assert _valid_geometry({}) == {}


def test_non_int_value_returns_empty():
    assert _valid_geometry({"x": "0", "y": 0, "width": 1000, "height": 700}) == {}
    assert _valid_geometry({"x": 0, "y": 0, "width": 1000.5, "height": 700}) == {}


def test_bool_value_rejected_even_though_bool_is_an_int_subclass():
    assert _valid_geometry({"x": True, "y": 0, "width": 1000, "height": 700}) == {}
    assert _valid_geometry({"x": 0, "y": 0, "width": 1000, "height": False}) == {}


def test_below_minimum_clamps_up_to_app_floor():
    geo = {"x": 0, "y": 0, "width": 500, "height": 300}
    out = _valid_geometry(geo)
    assert out["width"] == 980
    assert out["height"] == 680


def test_above_maximum_clamps_down_to_ceiling():
    geo = {"x": 0, "y": 0, "width": 50000, "height": 50000}
    out = _valid_geometry(geo)
    assert out["width"] == 10000
    assert out["height"] == 10000


def test_x_and_y_pass_through_negative_values_unclamped():
    # x/y are only rejected by type, never clamped (a monitor can be at a negative offset).
    geo = {"x": -1920, "y": -40, "width": 1000, "height": 700}
    out = _valid_geometry(geo)
    assert out["x"] == -1920
    assert out["y"] == -40


def test_fit_rect_to_work_area_shrinks_width():
    assert fit_rect_to_work_area(0, 20, 140, 60, (0, 0, 100, 100), (0, 0, 0, 0)) == (0, 20, 100, 60)


def test_fit_rect_to_work_area_shrinks_height():
    assert fit_rect_to_work_area(20, 0, 60, 140, (0, 0, 100, 100), (0, 0, 0, 0)) == (20, 0, 60, 100)


def test_fit_rect_to_work_area_moves_past_right_and_bottom():
    assert fit_rect_to_work_area(70, 80, 40, 30, (0, 0, 100, 100), (0, 0, 0, 0)) == (60, 70, 40, 30)


def test_fit_rect_to_work_area_moves_past_left_and_top():
    assert fit_rect_to_work_area(-10, -20, 40, 30, (0, 0, 100, 100), (0, 0, 0, 0)) == (0, 0, 40, 30)


def test_fit_rect_to_work_area_keeps_snapped_visible_edge():
    assert fit_rect_to_work_area(-7, 0, 114, 107, (0, 0, 100, 100), (7, 0, 7, 7)) == (-7, 0, 114, 107)


def test_fit_rect_to_work_area_keeps_already_fitting_rect():
    assert fit_rect_to_work_area(10, 20, 60, 50, (0, 0, 100, 100), (2, 3, 4, 5)) == (10, 20, 60, 50)


def test_fit_rect_to_work_area_handles_negative_origin():
    assert fit_rect_to_work_area(-180, 10, 80, 40, (-200, 0, 0, 100), (0, 0, 0, 0)) == (-180, 10, 80, 40)


def test_fit_rect_to_work_area_keeps_top_left_when_larger_in_both_directions():
    assert fit_rect_to_work_area(-20, -20, 140, 140, (0, 0, 100, 100), (0, 0, 0, 0)) == (0, 0, 100, 100)
