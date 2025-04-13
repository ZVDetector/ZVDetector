from zigpy.zcl.clusters.general import Basic, Groups, Identify, Scenes, OnOff, LevelControl, \
    Alarms, RSSILocation, Commissioning, Ota, PowerProfile, PollControl, \
    PowerConfiguration, DeviceTemperature, OnOffConfiguration, Time, AnalogInput, AnalogOutput, AnalogValue, \
    BinaryInput, BinaryOutput, BinaryValue, MultistateInput, MultistateOutput, MultistateValue, Partition, \
    ApplianceControl, KeepAlive

from zigpy.zcl.clusters.homeautomation import ElectricalMeasurement, ApplianceEventAlerts, ApplianceStatistics, \
    ApplianceIdentification, MeterIdentification, Diagnostic

from zigpy.zcl.clusters.measurement import IlluminanceMeasurement, IlluminanceLevelSensing, \
    TemperatureMeasurement, PressureMeasurement, FlowMeasurement, RelativeHumidity, OccupancySensing, \
    LeafWetness, SoilMoisture, PH, ElectricalConductivity, WindSpeed, CarbonMonoxideConcentration, \
    CarbonDioxideConcentration, EthyleneConcentration, EthyleneOxideConcentration, HydrogenConcentration, \
    HydrogenSulfideConcentration, NitricOxideConcentration, NitrogenDioxideConcentration, OxygenConcentration, \
    OzoneConcentration, SulfurDioxideConcentration, DissolvedOxygenConcentration, BromateConcentration, \
    ChlorineConcentration, ChloraminesConcentration, FecalColiformAndEColiFraction, FluorideConcentration, \
    HaloaceticAcidsConcentration, TotalTrihalomethanesConcentration, TotalColiformBacteriaFraction, Turbidity, \
    CopperConcentration, LeadConcentration, ManganeseConcentration, SulfateConcentration, \
    BromodichloromethaneConcentration, BromoformConcentration, ChlorodibromomethaneConcentration, \
    ChloroformConcentration, SodiumConcentration, PM25, FormaldehydeConcentration

from zigpy.zcl.clusters.protocol import GenericTunnel, BacnetProtocolTunnel, AnalogInputExtended, AnalogInputRegular, \
    AnalogValueExtended, AnalogOutputExtended, AnalogOutputRegular, AnalogValueRegular, BinaryOutputRegular, \
    BinaryOutputExtended, BinaryValueExtended, BinaryValueRegular, BinaryInputExtended, BinaryInputRegular, \
    MultistateInputExtended, MultistateInputRegular, MultistateOutputRegular, MultistateValueRegular, \
    MultistateOutputExtended, MultistateValueExtended

from zigpy.zcl.clusters.closures import Shade, DoorLock, WindowCovering

from zigpy.zcl.clusters.hvac import Thermostat, Pump, Fan, Dehumidification, UserInterface

from zigpy.zcl.clusters.security import IasZone, IasAce, IasWd

from zigpy.zcl.clusters.lightlink import LightLink

from zigpy.zcl.clusters.smartenergy import Metering

from zigpy.zcl.clusters.lighting import Color

import zigpy.zcl.foundation

import zigpy.types.basic
import zigpy.types.named
import zigpy.types.struct

GENERAL_ATTRIBUTE_MAP = {
    Basic.ep_attribute: Basic,
    Identify.ep_attribute: Identify,
    Groups.ep_attribute: Groups,
    Scenes.ep_attribute: Scenes,
    OnOff.ep_attribute: OnOff,
    LevelControl.ep_attribute: LevelControl,
    Alarms.ep_attribute: Alarms,
    RSSILocation.LocationMethod: RSSILocation,
    Commissioning.ep_attribute: Commissioning,
    Ota.ep_attribute: Ota,
    PowerProfile.ep_attribute: PowerProfile,
    PollControl.ep_attribute: PollControl,
    PowerConfiguration.ep_attribute: PowerConfiguration,
    DeviceTemperature.ep_attribute: DeviceTemperature,
    OnOffConfiguration.ep_attribute: OnOffConfiguration,
    Time.ep_attribute: Time,
    AnalogInput.ep_attribute: AnalogInput,
    AnalogOutput.ep_attribute: AnalogOutput,
    AnalogValue.ep_attribute: AnalogValue,
    BinaryInput.ep_attribute: BinaryInput,
    BinaryOutput.ep_attribute: BinaryOutput,
    BinaryValue.ep_attribute: BinaryValue,
    MultistateInput.ep_attribute: MultistateInput,
    MultistateOutput.ep_attribute: MultistateOutput,
    MultistateValue.ep_attribute: MultistateValue,
    Partition.ep_attribute: Partition,
    ApplianceControl.ep_attribute: ApplianceControl,
    KeepAlive.ep_attribute: KeepAlive
}


LIGHT_ATTRIBUTE_MAP = {
    Color.ep_attribute: Color,
    Ballast.ep_attribute: Ballast
}

HA_ATTRIBUTE_MAP = {
    ElectricalMeasurement.ep_attribute: ElectricalMeasurement,
    ApplianceEventAlerts.ep_attribute: ApplianceEventAlerts,
    ApplianceStatistics.ep_attribute: ApplianceStatistics,
    Diagnostic.ep_attribute: Diagnostic,
    MeterIdentification.ep_attribute: MeterIdentification,
    ApplianceIdentification.ep_attribute: ApplianceIdentification
}

MEASUREMENT_ATTRIBUTE_MAP = {
    BromateConcentration.ep_attribute: BromateConcentration,
    BromoformConcentration.ep_attribute: BromoformConcentration,
    BromodichloromethaneConcentration.ep_attribute: BromodichloromethaneConcentration,
    CopperConcentration.ep_attribute: CopperConcentration,
    ChloroformConcentration.ep_attribute: ChloroformConcentration,
    ChlorineConcentration.ep_attribute: ChlorineConcentration,
    ChloraminesConcentration.ep_attribute: ChloraminesConcentration,
    ChlorodibromomethaneConcentration.ep_attribute: ChlorodibromomethaneConcentration,
    CarbonDioxideConcentration.ep_attribute: CarbonDioxideConcentration,
    CarbonMonoxideConcentration.ep_attribute: CarbonMonoxideConcentration,
    DissolvedOxygenConcentration.ep_attribute: DissolvedOxygenConcentration,
    EthyleneConcentration.ep_attribute: EthyleneConcentration,
    ElectricalConductivity.ep_attribute: ElectricalConductivity,
    EthyleneOxideConcentration.ep_attribute: EthyleneConcentration,
    FlowMeasurement.ep_attribute: FlowMeasurement,
    FluorideConcentration.ep_attribute: FluorideConcentration,
    FormaldehydeConcentration.ep_attribute: FormaldehydeConcentration,
    FecalColiformAndEColiFraction.ep_attribute: FecalColiformAndEColiFraction,
    HydrogenConcentration.ep_attribute: HydrogenConcentration,
    HaloaceticAcidsConcentration.ep_attribute: HaloaceticAcidsConcentration,
    HydrogenSulfideConcentration.ep_attribute: HydrogenSulfideConcentration,
    IlluminanceMeasurement.ep_attribute: IlluminanceMeasurement,
    IlluminanceLevelSensing.ep_attribute: IlluminanceLevelSensing,
    LeafWetness.ep_attribute: LeafWetness,
    LeadConcentration.ep_attribute: LeadConcentration,
    ManganeseConcentration.ep_attribute: ManganeseConcentration,
    NitricOxideConcentration.ep_attribute: NitricOxideConcentration,
    NitrogenDioxideConcentration.ep_attribute: NitrogenDioxideConcentration,
    OccupancySensing.ep_attribute: OccupancySensing,
    OzoneConcentration.ep_attribute: OzoneConcentration,
    PH.ep_attribute: PH,
    PM25.ep_attribute: PM25,
    PressureMeasurement.ep_attribute: PressureMeasurement,
    RelativeHumidity.ep_attribute: RelativeHumidity,
    SoilMoisture.ep_attribute: SoilMoisture,
    SodiumConcentration.ep_attribute: SodiumConcentration,
    SulfateConcentration.ep_attribute: SulfateConcentration.ep_attribute,
    SulfurDioxideConcentration.ep_attribute: SulfurDioxideConcentration,
    Turbidity.ep_attribute: Turbidity,
    TemperatureMeasurement.ep_attribute: TemperatureMeasurement,
    TotalColiformBacteriaFraction.ep_attribute: TotalColiformBacteriaFraction,
    TotalTrihalomethanesConcentration.ep_attribute: TotalTrihalomethanesConcentration,
    WindSpeed.ep_attribute: WindSpeed
}


PROTOCOL_ATTRIBUTE_MAP = {
    GenericTunnel.ep_attribute: GenericTunnel,
    BacnetProtocolTunnel.ep_attribute: BacnetProtocolTunnel,
    AnalogInputExtended.ep_attribute: AnalogInputExtended,
    AnalogInputRegular.ep_attribute: AnalogInputRegular,
    AnalogOutputRegular.ep_attribute: AnalogOutputRegular,
    AnalogOutputExtended.ep_attribute: AnalogOutputExtended,
    AnalogValueRegular.ep_attribute: AnalogValueRegular,
    AnalogValueExtended.ep_attribute: AnalogValueExtended,
    BinaryInputRegular.ep_attribute: BinaryInputRegular,
    BinaryInputExtended.ep_attribute: BinaryInputExtended,
    BinaryOutputRegular.ep_attribute: BinaryOutputRegular,
    BinaryOutputExtended.ep_attribute: BinaryOutputExtended,
    BinaryValueRegular.ep_attribute: BinaryValueRegular,
    BinaryValueExtended.ep_attribute: BinaryValueExtended,
    MultistateInputRegular.ep_attribute: MultistateInputRegular,
    MultistateInputExtended.ep_attribute: MultistateInputExtended,
    MultistateOutputRegular.ep_attribute: MultistateOutputRegular,
    MultistateOutputExtended.ep_attribute: MultistateOutputExtended,
    MultistateValueRegular.ep_attribute: MultistateValueRegular,
    MultistateValueExtended.ep_attribute: MultistateValueExtended
}

HAVC_ATTRIBUTE_MAP = {
    Pump.ep_attribute: Pump,
    Fan.ep_attribute: Fan,
    Thermostat.ep_attribute: Thermostat,
    Dehumidification.ep_attribute: Dehumidification,
    UserInterface.ep_attribute: UserInterface
}

CLOSURES_ATTRIBUTE_MAP = {
    Shade.ep_attribute: Shade,
    DoorLock.ep_attribute: DoorLock,
    WindowCovering.ep_attribute: WindowCovering
}

LIGHTLINK_ATTRIBUTE_MAP = {}

SECURITY_ATTRIBUTE_MAP = {
    IasZone.ep_attribute: IasZone,
    IasWd.ep_attribute: IasWd,
    IasAce.ep_attribute: IasAce
}

