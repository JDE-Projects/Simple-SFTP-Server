"""Tests for _valid_geometry: pure validation of a saved window geometry dict.
See simple_sftp_server.py, "prefs (theme + window geometry)" section."""

from simple_sftp_server import _valid_geometry


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
