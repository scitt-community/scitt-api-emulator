# Copyright (c) SCITT Authors.
# Licensed under the MIT License.
import os
import textwrap

from scitt_emulator.plugin_helpers import entrypoint_style_load


def test_entrypoint_style_load_relative(tmp_path):
    plugin_path = tmp_path / "myplugin.py"

    plugin_path.write_text(
        textwrap.dedent(
            """
            def my_cool_plugin():
                return "Hello World"


            class MyCoolClass:
                @staticmethod
                def my_cool_plugin():
                    return my_cool_plugin()


            my_cool_dict = {
                "my_cool_plugin": my_cool_plugin,
            }
            """,
        )
    )

    for load_within_file in [
        "my_cool_plugin",
        "MyCoolClass.my_cool_plugin",
        "my_cool_dict.my_cool_plugin",
    ]:
        plugin_entrypoint_style_path = (
            str(plugin_path.relative_to(tmp_path).with_suffix("")).replace(
                os.path.sep, "."
            )
            + ":"
            + load_within_file
        )

        loaded = list(
            entrypoint_style_load(plugin_entrypoint_style_path, relative=tmp_path)
        )[0]

        os.chdir(tmp_path)

        loaded = list(
            entrypoint_style_load(plugin_entrypoint_style_path, relative=True)
        )[0]

        assert loaded() == "Hello World"
