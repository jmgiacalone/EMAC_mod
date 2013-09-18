// Only modify this file to include
// - function definitions (prototypes)
// - include files
// - extern variable definitions
// In the appropriate section

#ifndef EMAC_mod_H_
#define EMAC_mod_H_
#include "Arduino.h"
#include "variant.h"
#include "conf_eth.h"
#include <mini_ip.h>
#include <ethernet_phy.h>
#include <rmii.h>
//#include <include/emac.h>
#include <source/emac.c>
//#include <include/rstc.h>
#include <source/rstc.c>


//end of add your includes here
#ifdef __cplusplus
extern "C" {
#endif
void loop();
void setup();
#ifdef __cplusplus
} // extern "C"
#endif

//add your function definitions for the project EMAC_mod here




//Do not add code below this line
#endif /* EMAC_mod_H_ */
