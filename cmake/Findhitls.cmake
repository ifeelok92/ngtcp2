# - Try to find openHiTLS
# Once done this will define
#  HITLS_FOUND           - System has openHiTLS
#  HITLS_INCLUDE_DIR     - The openHiTLS include directories
#  HITLS_LIBRARIES       - The libraries needed to use openHiTLS

find_package(PkgConfig QUIET)
pkg_check_modules(PC_HITLS QUIET hitls)

find_path(HITLS_INCLUDE_DIR
  NAMES tls/hitls.h tls/hitls_quic_tls.h crypto/crypt_eal_cipher.h
  HINTS ${PC_HITLS_INCLUDE_DIRS}
)

foreach(_lib hitls_tls hitls_pki hitls_auth hitls_crypto hitls_bsl)
  find_library(HITLS_${_lib}_LIBRARY
    NAMES ${_lib}
    HINTS ${PC_HITLS_LIBRARY_DIRS}
  )
endforeach()

set(HITLS_LIBRARIES
  ${HITLS_hitls_tls_LIBRARY}
  ${HITLS_hitls_pki_LIBRARY}
  ${HITLS_hitls_auth_LIBRARY}
  ${HITLS_hitls_crypto_LIBRARY}
  ${HITLS_hitls_bsl_LIBRARY}
  pthread dl
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(hitls REQUIRED_VARS
                                  HITLS_INCLUDE_DIR HITLS_hitls_tls_LIBRARY
                                  HITLS_hitls_crypto_LIBRARY HITLS_hitls_bsl_LIBRARY)

if(HITLS_FOUND)
  # openHiTLS uses flat includes (<hitls.h>, <crypt_*.h>, <bsl_*.h>) with one
  # include path per component directory.
  set(HITLS_INCLUDE_DIRS
    "${HITLS_INCLUDE_DIR}/tls"
    "${HITLS_INCLUDE_DIR}/crypto"
    "${HITLS_INCLUDE_DIR}/bsl"
    "${HITLS_INCLUDE_DIR}/pki"
    "${HITLS_INCLUDE_DIR}/auth"
  )
endif()

mark_as_advanced(HITLS_INCLUDE_DIR)
foreach(_lib hitls_tls hitls_pki hitls_auth hitls_crypto hitls_bsl)
  mark_as_advanced(HITLS_${_lib}_LIBRARY)
endforeach()
