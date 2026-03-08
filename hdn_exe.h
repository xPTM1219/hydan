/*
 * $Id$
 * Created: 05/20/2004
 *
 * xvr (c) 2004
 * xvr@xvr.net
 */

#ifndef _HDN_EXE_H_
#define _HDN_EXE_H_

#include "hydan.h"

/*
 * returns a linked list of the sections in an executable
 */
hdn_sections_header_t *hdn_exe_get_sections (uint8_t *file_start);

/*
 * is a section code or not?
 */
inline char hdn_exe_section_is_code (hdn_sections_t *hs);

#endif//!HDN_EXE_H_
