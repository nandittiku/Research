#include<stdio.h>
#include<stdlib.h>
#include<iostream>
#include<assert.h>
#include<fstream>
#include<set>
#include<list>
#include<math.h>
#include<queue>
#include<stack>
#include<string>
#include<sstream>
#include<limits.h>
#include"async.h"
#include"tame.h"
//#include"parseopt.h"
//#include"qhash.h"
#include<tr1/unordered_map>

using namespace std;
using namespace std::tr1;

#define lookup_msg 1
#define lookup_reply_msg 2

#define ping_msg 3 
#define ping_reply_msg 4

#define get_pred_msg 5
#define stabilize_reply_msg 6
#define notify_msg 7 

#define recv_sign_msg 8

#define bootstrap_msg 9	// give me my succ list
#define bootstrap_get_pred_msg 10 
#define bootstrap_get_pred_reply_msg 11 
#define bootstrap_reply 12 // final reply with succ list

#define debug_state_msg 13
#define debug_state_reply_msg 14


//#define CLOSURE ptr<closure_t> __cls_g = NULL

int MAXID = 1048576;
const int m=20;	// log MAXID /log 2
//const int MAXID = 4096;
//const int m=12;	// log MAXID /log 2
short port=35000;
struct msg{
	unsigned int from;
	str hostname_from;
	unsigned int original_from;
	str hostname_original_from;
	unsigned int to;
	unsigned int value;
	unsigned int value2;
	unsigned int value3;
	unsigned int value4;
	str hostname_value;
	str hostname_value2;
	str hostname_value3;
	str hostname_value4;
	unsigned int ttl;
	unsigned int fingertable[3*m];	// the succ list, routing state
	stack<unsigned int> path;	// lookup stack
	set<unsigned int> failed_nodes;	// failed nodes that are encountered
	unsigned int fingertable_succ1[3*m];
	unsigned int fingertable_succ2[3*m];
	str hostnametable[3*m];
	str hostnametable_succ1[3*m];
	str hostnametable_succ2[3*m];

};

struct shadow{
	unsigned int id;
	unsigned int fingertable[3*m];	// the first 2m is the succ list and then comes the actual fingertable
	str hostnametable[3*m];
	unsigned int fingerid[3*m];
	unsigned int fingertable_succ1[3*m]; // succ1 of fingertable[i]
	str hostnametable_succ1[3*m];
	unsigned int fingertable_succ2[3*m]; // succ2 of fingertable[i]
	str hostnametable_succ2[3*m];
	int next;
};

class node{
	public:
	unsigned int id;
	str hostname;
	unsigned int fingertable[3*m];	// the first 2m is the succ list and then comes the actual fingertable
	unsigned int fingerid[3*m];
	str hostnametable[3*m];	// hostnames to connect to
	unsigned int fingertable_succ1[3*m]; // succ1 of fingertable[i]
	str hostnametable_succ1[3*m];
	unsigned int fingertable_succ2[3*m]; // succ2 of fingertable[i]
	str hostnametable_succ2[3*m];
	//unordered_map <unsigned int, string> map_id_name;	
	
	unsigned int pred;
	str hostname_pred;
	unsigned int pred1;
	int next;
	int alive;
	struct shadow  succ1;	// i maintain my succ1's fingers	
	struct shadow  succ2;	// i maintai4096y succ2's fingers	// instead of pred, its just easier to lookup succ2!
	// the above two data structures change drastically when my succ1 or succ2 change
	
	unsigned int pred_fingertable[3*m];
	unsigned int pred_fingertable_succ1[3*m];
	unsigned int pred_fingertable_succ2[3*m];
	unsigned int pred1_fingertable[3*m];
	unsigned int pred1_fingertable_succ1[3*m];
	unsigned int pred1_fingertable_succ2[3*m];

	// i think the above are certifications from the shadow nodes
	void lookup(struct msg);
	void lookup_reply(struct msg);
	void lookup_timeout();
	void fix_fingers();
	void stabilize();
	void stabilize_reply(struct msg);
	void stabilize_timeout();
	void notify(struct msg);
	void check_predecessor();
	void ping(struct msg);
	void ping_reply(struct msg);
	void ping_timeout();
	void get_pred(struct msg);
	void sign_state();
	void recv_sign(struct msg);
	void initiate_path();
	void extend_path();
	void closest_finger(unsigned int);
	/*void bootstrap(struct msg);
	void bootstrap_get_pred(struct msg);
	void bootstrap_get_pred_reply(struct msg);
	void bootstrap_reply(struct msg);*/
	void debug_state(struct msg);
	void debug_state_reply(struct msg);

};


