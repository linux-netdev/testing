.. SPDX-License-Identifier: GPL-2.0

=====================
ionic devlink support
=====================

This document describes the devlink features implemented by the ``ionic``
device driver.

Parameters
==========

The ``ionic`` driver implements the following driver-specific parameters.

.. list-table:: Driver-specific parameters implemented
   :widths: 5 5 5 85

   * - Name
     - Type
     - Mode
     - Description
   * - ``cmd_timeout``
     - u8
     - permanent
     - Command timeout in seconds, 0, or 5 (the default) to 255; values below
       the default are rejected, as the parameter is for cases where the
       default does not suffice. When set to a non-zero value, replaces the
       default timeout for device and admin queue commands, and the RDMA admin
       queue watchdog. A value of 0 restores the default. A larger value delays
       the firmware heartbeat stall check, which runs at twice this interval.
       On unresponsive firmware, a larger value also lets callers block for
       longer: each device or admin queue command can wait up to this value,
       other commands wait behind it, and RDMA verbs such as QP and CQ create
       can block for several times this value. A large setting may need a
       larger kernel.hung_task_timeout_secs. The value is stored in device NVM
       and takes effect on the next driver probe or device reset. Only
       available when the device firmware supports it.

Info versions
=============

The ``ionic`` driver reports the following versions

.. list-table:: devlink info versions implemented
   :widths: 5 5 90

   * - Name
     - Type
     - Description
   * - ``fw``
     - running
     - Version of firmware running on the device
   * - ``asic.id``
     - fixed
     - The ASIC type for this device
   * - ``asic.rev``
     - fixed
     - The revision of the ASIC for this device
