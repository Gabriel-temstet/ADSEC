"""PluginManager : decouverte, validation et filtrage des CheckPlugin.

Sources de decouverte :
1. Modules internes sous `adsec.rules.*` (paquet livre avec le produit).
2. Modules externes sous `adsec.plugins.*` (plugins additionnels).
3. Entry points `adsec.plugins` declares par des packages tiers installes.

Un plugin `intrusive=True` est EXCLU par defaut : il ne sera jamais
selectionne par `select_plugins()` sauf si `allow_intrusive=True` est
explicitement passe (et le scope doit lui-meme autoriser les actions
intrusives - voir ScopeManager.assert_intrusive_allowed).
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass
from importlib.metadata import entry_points
from types import ModuleType

from adsec.core.models.enums import AccessLevel, ScanProfile
from adsec.rules.base import CheckPlugin

_INTERNAL_PACKAGES = ("adsec.rules", "adsec.plugins")
_ENTRY_POINT_GROUP = "adsec.plugins"


class DuplicatePluginIdError(Exception):
    pass


@dataclass
class PluginLoadError:
    module_name: str
    error: str


class PluginManager:
    def __init__(self) -> None:
        self._plugins: dict[str, type[CheckPlugin]] = {}
        self._load_errors: list[PluginLoadError] = []

    @property
    def load_errors(self) -> list[PluginLoadError]:
        return list(self._load_errors)

    def discover(self) -> PluginManager:
        """Decouvre tous les plugins disponibles. Idempotent."""
        for package_name in _INTERNAL_PACKAGES:
            self._discover_in_package(package_name)
        self._discover_entry_points()
        return self

    def register(self, plugin_cls: type[CheckPlugin]) -> None:
        if plugin_cls.id in self._plugins and self._plugins[plugin_cls.id] is not plugin_cls:
            raise DuplicatePluginIdError(
                f"Un plugin avec l'id {plugin_cls.id!r} est deja enregistre "
                f"({self._plugins[plugin_cls.id].__name__} vs {plugin_cls.__name__})"
            )
        self._plugins[plugin_cls.id] = plugin_cls

    def all_plugins(self) -> list[type[CheckPlugin]]:
        return list(self._plugins.values())

    def get(self, plugin_id: str) -> type[CheckPlugin] | None:
        return self._plugins.get(plugin_id)

    def select_plugins(
        self,
        access_level: AccessLevel,
        profile: ScanProfile,
        allowed_categories: list[str] | None = None,
        allow_intrusive: bool = False,
    ) -> list[type[CheckPlugin]]:
        """Filtre les plugins compatibles avec le niveau d'acces, le profil
        de scan et l'autorisation (ou non) des actions intrusives."""
        selected = []
        for plugin_cls in self._plugins.values():
            if plugin_cls.intrusive and not allow_intrusive:
                continue
            instance_check = plugin_cls  # verification sur la classe, pas d'instanciation requise
            order = [
                AccessLevel.ANONYMOUS,
                AccessLevel.AUTHENTICATED,
                AccessLevel.AUDITOR,
                AccessLevel.PRIVILEGED,
            ]
            if order.index(access_level) < order.index(instance_check.required_permissions):
                continue
            if allowed_categories is not None and plugin_cls.category not in allowed_categories:
                continue
            selected.append(plugin_cls)
        return selected

    # -- internes -----------------------------------------------------

    def _discover_in_package(self, package_name: str) -> None:
        try:
            package = importlib.import_module(package_name)
        except ImportError as exc:
            self._load_errors.append(PluginLoadError(package_name, str(exc)))
            return

        if not hasattr(package, "__path__"):
            return

        for module_info in pkgutil.walk_packages(package.__path__, prefix=f"{package_name}."):
            try:
                module = importlib.import_module(module_info.name)
            except Exception as exc:  # noqa: BLE001 - isolation d'un module defaillant
                self._load_errors.append(PluginLoadError(module_info.name, str(exc)))
                continue
            self._register_from_module(module)

    def _discover_entry_points(self) -> None:
        try:
            eps = entry_points(group=_ENTRY_POINT_GROUP)
        except Exception as exc:  # noqa: BLE001
            self._load_errors.append(PluginLoadError("<entry_points>", str(exc)))
            return
        for ep in eps:
            try:
                plugin_cls = ep.load()
            except Exception as exc:  # noqa: BLE001
                self._load_errors.append(PluginLoadError(ep.name, str(exc)))
                continue
            if inspect.isclass(plugin_cls) and issubclass(plugin_cls, CheckPlugin):
                self.register(plugin_cls)

    def _register_from_module(self, module: ModuleType) -> None:
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, CheckPlugin)
                and obj is not CheckPlugin
                and obj.__module__ == module.__name__
            ):
                self.register(obj)
