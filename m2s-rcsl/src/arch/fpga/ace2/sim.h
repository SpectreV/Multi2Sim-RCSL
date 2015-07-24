#ifndef __ACE_SIM_H__
#define __ACE_SIM_H__

#include "ace.h"

void ace_sim_activities(Abc_Ntk_t * ntk, Vec_Ptr_t * node_vec, int max_cycles,
		Vec_Int_t * delays);

#endif
