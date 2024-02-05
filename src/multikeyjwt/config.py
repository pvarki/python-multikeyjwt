"""Config helper"""
import typing
import os


try:
    from starlette.config import Config
    from starlette.datastructures import Secret

    _CONFIG = Config()  # not supporting .env files anymore because https://github.com/encode/starlette/discussions/2446

    def starlette_config_wrapper(
        key: str,
        default: typing.Optional[str] = None,
        cast: typing.Optional[typing.Callable[[typing.Any], typing.Any]] = None,
    ) -> typing.Any:
        """Wrap starlettes config to keep type-checking sane with the missing starlette -case"""
        if cast:
            return _CONFIG(key, default=default, cast=cast)
        return _CONFIG(key, default=default)

    ENVCONFIG = starlette_config_wrapper
except ImportError:
    # Vendor the Secret from starlette
    class Secret:  # type: ignore
        """
        Holds a string value that should not be revealed in tracebacks etc.
        You should cast the value to `str` at the point it is required.
        """

        def __init__(self, value: str):
            self._value = value

        def __repr__(self) -> str:
            class_name = self.__class__.__name__
            return f"{class_name}('**********')"

        def __str__(self) -> str:
            return self._value

        def __bool__(self) -> bool:
            return bool(self._value)

    def config_wrapper(
        key: str,
        default: typing.Optional[str] = None,
        cast: typing.Optional[typing.Callable[[typing.Any], typing.Any]] = None,
    ) -> typing.Any:
        """quick wrapper for os.getenv for users that do not have Starlette"""
        val = os.getenv(key, default=default)

        def _perform_cast(
            key: str, value: typing.Any, cast: typing.Optional[typing.Callable[..., typing.Any]] = None
        ) -> typing.Any:
            if cast is None or value is None:
                return value
            if cast is bool and isinstance(value, str):
                mapping = {"true": True, "1": True, "false": False, "0": False}
                value = value.lower()
                if value not in mapping:
                    raise ValueError(f"Config '{key}' has value '{value}'. Not a valid bool.")
                return mapping[value]
            try:
                return cast(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Config '{key}' has value '{value}'. Not a valid {cast.__name__}.") from exc

        return _perform_cast(key, val, cast)

    ENVCONFIG = config_wrapper

__all__ = ["ENVCONFIG", "Secret"]
