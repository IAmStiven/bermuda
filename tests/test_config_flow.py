"""Test Bermuda BLE Trilateration config flow."""

from __future__ import annotations

from homeassistant import config_entries
from homeassistant import data_entry_flow
from homeassistant.core import HomeAssistant

# from homeassistant.core import HomeAssistant  # noqa: F401
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.bermuda.const import DOMAIN
from custom_components.bermuda.const import NAME

# from .const import MOCK_OPTIONS
from .const import MOCK_CONFIG
from .const import MOCK_OPTIONS_GLOBALS


# Here we simiulate a successful config flow from the backend.
# Note that we use the `bypass_get_data` fixture here because
# we want the config flow validation to succeed during the test.
async def test_successful_config_flow(hass, bypass_get_data):
    """Test a successful config flow."""
    # Initialize a config flow
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})

    # Check that the config flow shows the user form as the first step
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"

    # If a user were to enter `test_username` for username and `test_password`
    # for password, it would result in this function call
    result = await hass.config_entries.flow.async_configure(result["flow_id"], user_input=MOCK_CONFIG)

    # Check that the config flow is complete and a new entry is created with
    # the input data
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["title"] == NAME
    assert result["data"] == {"source": "user"}
    assert result["options"] == {}
    assert result["result"]


# In this case, we want to simulate a failure during the config flow.
# We use the `error_on_get_data` mock instead of `bypass_get_data`
# (note the function parameters) to raise an Exception during
# validation of the input config.
async def test_failed_config_flow(hass, error_on_get_data):
    """Test a failed config flow due to credential validation failure."""

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"

    result = await hass.config_entries.flow.async_configure(result["flow_id"], user_input=MOCK_CONFIG)

    assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
    assert result.get("errors") is None


# Our config flow also has an options flow, so we must test it as well.
async def test_options_flow(hass: HomeAssistant, setup_bermuda_entry: MockConfigEntry):
    """Test an options flow."""
    # Go through options flow
    result = await hass.config_entries.options.async_init(setup_bermuda_entry.entry_id)

    # Verify that the first options step is a user form
    assert result.get("type") == FlowResultType.MENU
    assert result.get("step_id") == "init"

    # select the globalopts menu option
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "globalopts"}
    )

    assert result.get("type") == FlowResultType.FORM
    assert result.get("step_id") == "globalopts"

    # Enter some fake data into the form
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input=MOCK_OPTIONS_GLOBALS,
    )

    # Verify that the flow finishes
    assert result.get("type") == FlowResultType.CREATE_ENTRY
    assert result.get("title") == NAME

    # Verify that the options were updated
    assert setup_bermuda_entry.options == MOCK_OPTIONS_GLOBALS


async def test_find_my_import_update_remove(hass, setup_bermuda_entry):
    """Import, replace and remove keys through the real options flow."""
    import json
    from custom_components.bermuda.const import CONF_DEVICES, CONF_FIND_MY
    from custom_components.bermuda.find_my import accessory_address, parse_accessory
    from .test_find_my import synthetic_export

    entry = setup_bermuda_entry
    export = synthetic_export()
    for name in ("First name", "Updated tag"):
        export["name"] = name
        result = await hass.config_entries.options.async_init(entry.entry_id)
        result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "findmy"})
        result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "findmy_add"})
        # Invalid input must stay on the form, without repeating sensitive values.
        bad = await hass.config_entries.options.async_configure(result["flow_id"], {"accessory_json": "{}"})
        assert bad["errors"] == {"base": "invalid_findmy_export"}
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], {"accessory_json": json.dumps(export)}
        )
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert len(result["data"][CONF_FIND_MY]) == 1
        assert result["data"][CONF_FIND_MY][0]["name"] == name
        assert accessory_address(parse_accessory(json.dumps(export))).upper() in result["data"][CONF_DEVICES]
        await hass.async_block_till_done()
        coordinator = entry.runtime_data.coordinator
        assert CONF_FIND_MY not in coordinator.options
        assert len([d for d in coordinator.devices if d.startswith("findmy:")]) == 1

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "findmy"})
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "findmy_remove"})
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"tags": [export["identifier"]]})
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_FIND_MY] == []
    assert not any(address.startswith("FINDMY:") for address in result["data"][CONF_DEVICES])
    await hass.async_block_till_done()
    assert not entry.runtime_data.coordinator._find_my_matches
