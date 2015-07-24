#include "ace.h"
#include "sim.h"

#include "cudd.h"

void get_pi_values(Abc_Ntk_t * ntk, Vec_Ptr_t * nodes, int cycle) {
	Abc_Obj_t * obj;
	Ace_Obj_Info_t * info;
	int i;
	double prob0to1, prob1to0, rand_num;

	//Vec_PtrForEachEntry(Abc_Obj_t *, nodes, obj, i)
	Abc_NtkForEachObj(ntk, obj, i)
	{
		info = Ace_ObjInfo(obj);
		info->cycle = -1;
		if (Abc_ObjType(obj) == ABC_OBJ_PI) {
			info->cycle = 0;
			if (info->values) {
				if (info->status == ACE_UNDEF) {
					info->status = ACE_NEW;
					if (info->values[cycle] == 1) {
						info->value = 1;
						info->num_toggles = 0;
						info->num_ones = 1;
					} else {
						info->value = 0;
						info->num_toggles = 0;
						info->num_ones = 0;
					}
				} else {
					switch (info->value) {
					case 0:
						if (info->values[cycle] == 1) {
							info->value = 1;
							info->status = ACE_NEW;
							info->num_toggles++;
							info->num_ones++;
						} else {
							info->status = ACE_OLD;
						}
						break;

					case 1:
						if (info->values[cycle] == 0) {
							info->value = 0;
							info->status = ACE_NEW;
							info->num_toggles++;
						} else {
							info->num_ones++;
							info->status = ACE_OLD;
						}
						break;

					default:
						printf("Bad Value\n");
						assert(0);
						break;
					}
				}
			} else {
				prob0to1 = ACE_P0TO1(info->static_prob, info->switch_prob);
				prob1to0 = ACE_P1TO0(info->static_prob, info->switch_prob);

				rand_num = (double) rand() / (double) RAND_MAX;

				if (info->status == ACE_UNDEF) {
					info->status = ACE_NEW;
					if (rand_num < prob0to1) {
						info->value = 1;
						info->num_toggles = 0;
						info->num_ones = 1;
					} else {
						info->value = 0;
						info->num_toggles = 0;
						info->num_ones = 0;
					}
				} else {
					switch (info->value) {
					case 0:
						if (rand_num < prob0to1) {
							info->value = 1;
							info->status = ACE_NEW;
							info->num_toggles++;
							info->num_ones++;
						} else {
							info->status = ACE_OLD;
						}
						break;

					case 1:
						if (rand_num < prob1to0) {
							info->value = 0;
							info->status = ACE_NEW;
							info->num_toggles++;
						} else {
							info->num_ones++;
							info->status = ACE_OLD;
						}
						break;

					default:
						printf("Bad value\n");
						assert(FALSE);
						break;
					}
				}
			}
		}
	}
}

int * getFaninValues(Abc_Obj_t * obj_ptr) {
	Abc_Obj_t * fanin;
	int i;
	Ace_Obj_Info_t * info;
	int * faninValues;

	Abc_ObjForEachFanin(obj_ptr, fanin, i)
	{
		info = Ace_ObjInfo(fanin);
		if (info->status == ACE_UNDEF) {
			printf("Fan-in is undefined\n");
			assert(FALSE);
		} else if (info->status == ACE_NEW) {
			break;
		}
	}

	if (i >= Abc_ObjFaninNum(obj_ptr)) {
		// inputs haven't changed
		return NULL;
	}

	faninValues = malloc(Abc_ObjFaninNum(obj_ptr) * sizeof(int));
	Abc_ObjForEachFanin(obj_ptr, fanin, i)
	{
		info = Ace_ObjInfo(fanin);
		faninValues[i] = info->value;
	}

	return faninValues;
}

ace_status_t getFaninStatus(Abc_Obj_t * obj_ptr) {
	Abc_Obj_t * fanin;
	int i;
	Ace_Obj_Info_t * info;

	Abc_ObjForEachFanin(obj_ptr, fanin, i)
	{
		info = Ace_ObjInfo(fanin);
		if (info->status == ACE_UNDEF) {
			return ACE_UNDEF;
		}
	}

	Abc_ObjForEachFanin(obj_ptr, fanin, i)
	{
		info = Ace_ObjInfo(fanin);
		if (info->status == ACE_NEW || info->status == ACE_SIM) {
			return ACE_NEW;
		}
	}

	return ACE_OLD;
}

void evaluate_circuit(Abc_Ntk_t * ntk, Vec_Ptr_t * node_vec) {
	Abc_Obj_t * obj, *fanin;
	Ace_Obj_Info_t * info;
	int i, j, cycle;
	int value;
	int * faninValues;
	ace_status_t status;
	DdNode * dd_node;

	Vec_PtrForEachEntry(node_vec, obj, i)
	{
		info = Ace_ObjInfo(obj);

		switch (Abc_ObjType(obj)) {
		case ABC_OBJ_PI:
		case ABC_OBJ_BO:
			break;

		case ABC_OBJ_PO:
		case ABC_OBJ_BI:
		case ABC_OBJ_LATCH:
		case ABC_OBJ_NODE:
			status = getFaninStatus(obj);
			switch (status) {
			case ACE_UNDEF:
				info->status = ACE_UNDEF;
				break;
			case ACE_OLD:
				info->status = ACE_OLD;
				info->num_ones += info->value;
				break;
			case ACE_NEW:
				if (Abc_ObjIsNode(obj)) {
					faninValues = getFaninValues(obj);
					assert(faninValues);
					dd_node = Cudd_Eval(ntk->pManFunc, obj->pData, faninValues);
					assert(Cudd_IsConstant(dd_node));
					if (dd_node == Cudd_ReadOne(ntk->pManFunc)) {
						value = 1;
					} else if (dd_node == Cudd_ReadLogicZero(ntk->pManFunc)) {
						value = 0;
					} else {
						assert(0);
					}
					free(faninValues);
				} else {
					Ace_Obj_Info_t * fanin_info = Ace_ObjInfo(
							Abc_ObjFanin0(obj));
					value = fanin_info->value;
				}

				if (info->value != value || info->status == ACE_UNDEF) {
					info->value = value;
					if (info->status != ACE_UNDEF) {
						/* Don't count the first value as a toggle */
						info->num_toggles++;
					}
					info->status = ACE_NEW;
				} else {
					info->status = ACE_OLD;
				}
				info->num_ones += info->value;
				break;
			default:
				assert(0);
				break;
			}
			break;
		default:
			assert(0);
			break;
		}

		cycle = 0;
		Abc_ForEachFanin(obj, fanin, j)
		{
			info = Ace_ObjInfo(fanin);
			if (info->cycle == -1) {
				Ace_ObjInfo(obj)->cycle = -1;
				break;
			}
			cycle = MAX(cycle, Ace_ObjInfo(fanin)->cycle);
		}


	}
}

void update_FF_and_Pos(Abc_Ntk_t * ntk, int cycle) {
	Abc_Obj_t * obj;
	int i;
	Ace_Obj_Info_t * bi_fanin_info;
	Ace_Obj_Info_t * bi_info;
	Ace_Obj_Info_t * latch_info;
	Ace_Obj_Info_t * bo_info;

	Abc_NtkForEachLatch(ntk, obj, i)
	{
		bi_fanin_info = Ace_ObjInfo(Abc_ObjFanin0(Abc_ObjFanin0(obj)));
		bi_info = Ace_ObjInfo(Abc_ObjFanin0(obj));
		bo_info = Ace_ObjInfo(Abc_ObjFanout0(obj));
		latch_info = Ace_ObjInfo(obj);

		// Value
		bi_info->value = bi_fanin_info->value;
		latch_info->value = bi_fanin_info->value;
		bo_info->value = bi_fanin_info->value;

		// Status
		bi_info->status = bi_fanin_info->status;
		latch_info->status = bi_fanin_info->status;
		bo_info->status = bi_fanin_info->status;

		// Ones
		bi_info->num_ones = bi_fanin_info->num_ones;
		latch_info->num_ones = bi_fanin_info->num_ones;
		bo_info->num_ones = bi_fanin_info->num_ones;

		// Toggles
		bi_info->num_toggles = bi_fanin_info->num_toggles;
		latch_info->num_toggles = bi_fanin_info->num_toggles;
		bo_info->num_toggles = bi_fanin_info->num_toggles;
	}

	Abc_NtkForEachPo(ntk, obj, i)
	{
		bi_info = Ace_ObjInfo(Abc_ObjFanin0(obj));
		Ace_ObjInfo(obj)->values[cycle] = bi_info->value;
	}
}

void ace_sim_activities(Abc_Ntk_t * ntk, Vec_Ptr_t * nodes, int num_vectors,
		Vec_Int_t * delays) {
	Abc_Obj_t * obj;
	Ace_Obj_Info_t * info;
	int i, j, delay;

	assert(num_vectors > 0);
	assert(delays->nCap == num_vectors);

	srand((unsigned) time(NULL));

	//Vec_PtrForEachEntry(Abc_Obj_t *, nodes, obj, i)
	Abc_NtkForEachObj(ntk, obj, i)
	{
		info = Ace_ObjInfo(obj);
		info->value = 0;

		if (Abc_ObjType(obj) == ABC_OBJ_BO) {
			info->status = ACE_NEW;
		} else {
			info->status = ACE_UNDEF;
		}
		info->num_ones = 0;
		info->num_toggles = 0;
	}

	/* Major Change: Hao Liang
	 * Input: Only allow vector inputs, and each line of vector inputs presents one task.
	 * Output: the output of each line of vector inputs, and the delay associated with it.
	 */

	Vec_Ptr_t * logic_nodes = Abc_NtkDfs(ntk, TRUE);
	for (i = 0; i < num_vectors; i++) {
		get_pi_values(ntk, nodes, i);
		while (!Vec_IntEntry(delays, i)) {
			evaluate_circuit(ntk, logic_nodes, &Vec_IntArray(delays)[i]);
			update_FF_and_Pos(ntk, &Vec_IntArray(delays)[i]);
		}
	}

	//Vec_PtrForEachEntry(Abc_Obj_t *, nodes, obj, i)
	Abc_NtkForEachObj(ntk, obj, i)
	{

		info = Ace_ObjInfo(obj);
		info->static_prob = info->num_ones / (double) num_vectors;
		assert(info->static_prob >= 0.0 && info->static_prob <= 1.0);
		info->switch_prob = info->num_toggles / (double) num_vectors;
		assert(info->switch_prob >= 0.0 && info->switch_prob <= 1.0);

		assert(info->switch_prob - EPSILON <= 2.0 * (1.0 - info->static_prob));
		assert(info->switch_prob - EPSILON <= 2.0 * (info->static_prob));

		info->status = ACE_SIM;
	}
}
