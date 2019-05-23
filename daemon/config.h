/**
 * Copyright 2018-2019 Shawn Anastasio
 *
 * This file is part of libkvmchan.
 *
 * libkvmchan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libkvmchan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libkvmchan.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * This file contains platform-specific configuration options
 */

#ifndef KVMCHAND_CONFIG_H
#define KVMCHAND_CONFIG_H

// VFIO mode configuration
#if defined(__powerpc64__) && !defined(PPC64_FORCE_NOIOMMU)
    // On ppc64, we have a vIOMMU
    #define USE_VFIO_SPAPR 1
#else
    // On other platforms, fallback to NOIOMMU
    #define USE_VFIO_NOIOMMU 1
#endif

#endif // KVMCHAND_CONFIG_H
