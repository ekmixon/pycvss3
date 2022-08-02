#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Aggregated Vulnerability Database Community


class Value:
    def __init__(self, **entries):
        self.__dict__.update(entries)


class Metrics:
    """
    This class returns the metric values as defined by the CVSS v3 specification doc. https://www.first.org/cvss/specification-document
    I added not_defined key to base metrics to deal with the Modified Base Metrics as they have the same values
    as the corresponding Base Metrics
    """

    # Base Metrics
    attack_vector = Value(
        not_defined=0.85,
        network=0.85,
        adjacent_network=0.62,
        local=0.55,
        physical=0.2,
    )

    attack_complexity = Value(not_defined=0.77, low=0.77, high=0.44)
    privileges_required = Value(not_defined=0.85, none=0.85, low=0.62, high=0.27)
    privileges_required_changed = Value(
        not_defined=0.85, none=0.85, low=0.68, high=0.5
    )

    user_interaction = Value(not_defined=0.85, none=0.85, required=0.62)
    cia_impact = Value(not_defined=0.56, high=0.56, low=0.22, none=float(0))

    # Temporal Metrics
    exploit_code_maturity = Value(
        not_defined=1.0,
        high=float(1),
        functional=0.97,
        proof_of_concept=0.94,
        unproven=0.91,
    )

    remediation_level = Value(
        not_defined=1.0,
        unavailable=float(1),
        workaround=0.97,
        temporary_fix=0.96,
        official_fix=0.95,
    )

    report_confidence = Value(
        not_defined=1.0, confirmed=float(1), reasonable=0.96, unknown=0.92
    )


    # Environmental Metrics
    cia_requirement = Value(not_defined=1.0, high=1.5, medium=1.0, low=0.5)
