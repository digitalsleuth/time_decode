from dataclasses import dataclass, field
from PyQt6.QtGui import QColor, QPalette
from time_decode._vendor.qt_themes import get_themes, update_palette


@dataclass(frozen=True)
class Scheme:
    window: str
    base: str
    alternate: str
    text: str
    highlight: str
    highlight_text: str
    match: str
    match_text: str
    theme: object = field(default=None, compare=False, repr=False)


CLASSIC = Scheme(
    window="white",
    base="white",
    alternate="#EAF6FF",
    text="black",
    highlight="#1644b9",
    highlight_text="white",
    match="lightgreen",
    match_text="black",
)
NAME_WORDS = {"github": "GitHub"}
DEFAULT_SCHEME = "Nord"


def from_theme(theme):
    dark = theme.is_dark_theme()
    highlight_text = theme.mantle if theme.primary.valueF() > 0.5 else theme.text
    match_text = theme.mantle if theme.green.valueF() > 0.5 else theme.text
    return Scheme(
        window=theme.base.name(),
        base=(theme.mantle if dark else theme.crust).name(),
        alternate=(theme.base if dark else theme.mantle).name(),
        text=theme.text.name(),
        highlight=theme.primary.name(),
        highlight_text=highlight_text.name(),
        match=theme.green.name(),
        match_text=match_text.name(),
        theme=theme,
    )


def display_name(name):
    return " ".join(NAME_WORDS.get(word, word.title()) for word in name.split("_"))


def themed_schemes():
    schemes = {
        display_name(name): from_theme(theme) for name, theme in get_themes().items()
    }
    return dict(sorted(schemes.items()))


SCHEMES = {"Classic": CLASSIC, **themed_schemes()}


def available_schemes():
    return dict(SCHEMES)


def default_scheme():
    return SCHEMES.get(DEFAULT_SCHEME, CLASSIC)


def mix(first, second, amount):
    return QColor.fromRgbF(
        first.redF() * (1 - amount) + second.redF() * amount,
        first.greenF() * (1 - amount) + second.greenF() * amount,
        first.blueF() * (1 - amount) + second.blueF() * amount,
    )


def build_palette(scheme, base_palette=None):
    if scheme.theme is not None:
        palette = QPalette(base_palette) if base_palette is not None else QPalette()
        update_palette(palette, scheme.theme)
        return palette
    window, base, alternate = (
        QColor(scheme.window),
        QColor(scheme.base),
        QColor(scheme.alternate),
    )
    text = QColor(scheme.text)
    highlight, highlight_text = QColor(scheme.highlight), QColor(scheme.highlight_text)
    dim = mix(text, window, 0.5)
    palette = QPalette(window, window)
    roles = QPalette.ColorRole
    for role, color in (
        (roles.Window, window),
        (roles.WindowText, text),
        (roles.Base, base),
        (roles.AlternateBase, alternate),
        (roles.Text, text),
        (roles.Button, window),
        (roles.ButtonText, text),
        (roles.BrightText, text),
        (roles.ToolTipBase, base),
        (roles.ToolTipText, text),
        (roles.Highlight, highlight),
        (roles.HighlightedText, highlight_text),
        (roles.Link, highlight),
        (roles.LinkVisited, highlight),
        (roles.PlaceholderText, dim),
    ):
        palette.setColor(role, color)
    for role in (roles.WindowText, roles.Text, roles.ButtonText, roles.PlaceholderText):
        palette.setColor(QPalette.ColorGroup.Disabled, role, dim)
    return palette
