/*
 * $Id: hydan.c,v 1.5 2003/01/19 02:02:21 xvr Exp $
 * Created: 08/16/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#include "hydan.h"

int main (int argc, char **argv)
{
    int ret = 1;

    if (strstr (argv[0], "hydan-decode"))     ret=hdn_decode_main (argc, argv);
    else if (strstr (argv[0], "hydan-stats")) ret=hdn_stats_main  (argc, argv);
    else if (strstr (argv[0], "hydan"))       ret=hdn_embed_main  (argc, argv);
    else fprintf (stderr, "use 'hydan' or 'hydan-decode'\n");

    return ret;
}
