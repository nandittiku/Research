#include<stdio.h>
#include<stdlib.h>
#include<iostream>
#include<assert.h>
#include<fstream>
#include<set>
#include<list>
#include<math.h>
#include <limits.h>
#include<queue>
#include<stack>
#include <algorithm>
/* #include <ext/hash_map> */
#include <set>
#include<tr1/unordered_map>
using namespace std::tr1;
using namespace __gnu_cxx;
using namespace std;


#define DISABLE_STABILIZE 1 // disable stabilize function. used for testing lookups etc.

#define DEBUG 1
#define CREATE_RANDOMNESS 0
int SINGLE_SUCCESSOR_IN_LIST = 1;
int ENABLE_DHT_LEVEL_ATTACK = 1;

long int MAXID = 1048576;
const int m=20;	// log MAXID /log 2
/* const int MAXID = 4096; */
/* const int m=12;	// log MAXID /log 2 */
const int TIMEOUT=2;	// 1 second timeout...is this OK? 
const int rDHT = 2*m;  // for stabilizing successor and pred. list
int rLookup = 1;     // for secure lookup
int fixingFingersMode = 0;

// i have decided to go for a priority queue based simulation; the caveat is that code cant be directly implemented;
// on the other hand, simulation is easier and i'm more familiar with this model

// start stabilize and checkpredecessor only when previous ones have finished (after a timeout)
// before a lookup ..insert yourself in path and make ttl=0

// stabilize can be easily secured by asking all succs about their neighbourhood succ+predinformation
// fix_fingers can call secure_lookup instead of lookup
// this results in a secure dht design
// next we shall convert this into a redundant structured topology
// lets assume that r=2, i.e. each node has a two shadows, the first and second succs

// i have assumed that lookup returns the shadows as well.

// shadows give signatures periodically to nodes...this can be done in the notify function..but i'll do it in a separate function
// nodes periodically make paths for anonymous communication...record the unrelaibility of this
// make path and use it for 10 minutes and then make another one

double Clock;

struct msg{
  unsigned int from; 
  unsigned int origin; // lookup request origin
  int lookupId;
  unsigned int to;
  unsigned int value;
  unsigned int value2;
  unsigned int value3;
  unsigned int value4;
  unsigned int ttl;
  unsigned int fingertable[3*m];	// the succ list, routing state
  unsigned int predList[2*m];	// the pred list
  stack<unsigned int> path;	// lookup stack
  set<unsigned int> failed_nodes;	// failed nodes that are encountered
  unsigned int fingertable_succ1[3*m];
  unsigned int fingertable_succ2[3*m];
  int lookuptype;
};

enum LOOKUP_TYPE{ME, SUCC1, SUCC2};

class Event{
	
  friend bool operator <(const Event& e1, const Event& e2){
    return e2._etime < e1._etime;
  }		

  friend bool operator ==(const Event& e1,const Event& e2){
    return e2._etime==e1._etime;
  }
 public:
  Event(){};
  enum EvtType{node_dead, node_alive,lookup,lookup_reply, fix_fingers, stabilize, get_pred, stabilize_reply,notify, check_predecessor, ping, ping_reply, ping_timeout, stabilize_timeout, sign_state, recv_sign, initiate_path, extend_path, authenticateReply, authenticateRequest, getSuccAndPredRequest, getSuccAndPredReply, stabilizeSuccessorListRequest, stabilizeSuccessorList, stabilizeSuccessorListAuthenticate, secure_lookup, secure_lookupReply, secure_lookupRequest};
 Event(EvtType type, double etime, int id, struct msg message):_type(type),_etime(etime),_id(id),_message(message){}
  EvtType get_type(){return _type;}
  double get_time(){return _etime;}
  unsigned int get_id(){return _id;}
  struct msg get_message(){return _message;}
 protected:
  EvtType _type;
  double _etime;
  unsigned int _id;
  struct msg _message;
};

priority_queue<Event> FutureEventList;

struct shadow{
  unsigned int id;
  // whats the difference between fingertable and fingerid?
  unsigned int fingertable[3*m];	// the first 2m is the succ list and then comes the actual fingertable
  unsigned int fingerid[3*m];
  unsigned int fingertable_succ1[3*m]; // succ1 of fingertable[i]
  unsigned int fingertable_succ2[3*m]; // succ2 of fingertable[i]
  int next;
};

enum status {AUTHENTICATED, INVALID, WAITING};


struct node{
  unsigned int ipaddress;
  unsigned int id;
  unsigned int fingertable[3*m];	// the first 2m is the succ list and then comes the actual fingertable
  unsigned int fingerid[3*m];

  unsigned int predList[2*m];  // pred list of the node

  unsigned int fingertable_succ1[3*m]; // succ1 of fingertable[i]
  unsigned int fingertable_succ2[3*m]; // succ2 of fingertable[i]

  	
  unsigned int pred;
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


  // needed for stabilization of DHT
  set<unsigned int> possibleSuccessors; // let these store the nodeid
  set<unsigned int> possiblePred; // let these store the nodeid
  unordered_map<unsigned int, unsigned int> possibleSuccessorsIP; // let these store the ip
  unordered_map<unsigned int, int> possibleSuccessorsStatus;
  unordered_map<unsigned int, int> possiblePredStatus;

  // needed just for testing lookup success rate
  set<unsigned int> alreadyLookedUpList;
  int iAmMalicious; // am I a malicious node?

  // for DHT lookup
  set<unsigned int> fixFingersSet; 
};


struct node *allnodes;
set<unsigned int> maliciousNodeList;
unsigned int *allnodesIds;

int num_nodes,check_predecessor_timer, stabilize_timer,fix_fingers_timer, guard_timer, simulation_time,mean_alive, sign_timer, path_timer;
double mean_alive_rate;
set<unsigned int> idlist,idlist_alive;
unordered_map<unsigned int, int> map;
double num_count=0, num_ttl=0;
double num_new_lookup=0;
void init(struct node *n);	// ok
void state_init_oracle(struct node *n);	// ok
unsigned int succ(unsigned int id);	// ok
void lookup(Event evt, struct node *n);
void lookup_reply(Event evt, struct node *n);
void lookup_timeout(Event evt, struct node *n);
void fix_fingers(Event evt, struct node *n);
void stabilize(Event evt, struct node*n);
void stabilize_reply(Event evt, struct node *n);
void stabilize_timeout(Event evt, struct node *n);
void notify(Event evt, struct node *n);
void check_predecessor(Event evt,struct node *n);
void ping(Event evt, struct node *n);
void ping_reply(Event evt, struct node *n);
void ping_timeout(Event evt, struct node *n);
void get_pred(Event evt, struct node *n);
unsigned int simCanon_NodeId_IncreasingDistance(unsigned int idsrc, unsigned int iddest);
unsigned int simCanon_NodeId_Closer(unsigned int idsrc1, unsigned int idsrc2, unsigned int iddest);
void node_dead(Event evt, struct node *n);
void node_alive(Event evt, struct node *n);	
double exponential_stream(double mean);
unsigned int succ_alive(unsigned int id);
void sign_state(Event evt, struct node *n);
void recv_sign(Event evt, struct node *n);
void initiate_path(Event evt, struct node *n);
void extend_path(Event evt, struct node *n);
void debug(const char* msg);
// nandits methods
void stabilizeSuccessorList (Event evt, struct node *n);
void stabilizeSuccessorListRequest (Event evt, struct node *n);
void authenticate ( unsigned int from, unsigned int to, unsigned int toIP );
void authenticateRequest (Event evt, struct node *n);
void authenticateReply (Event evt, struct node *n);
unsigned int hashIP(unsigned int ipaddress);
void authenticateReply (Event evt, struct node *n);
void getSuccAndPredRequest (Event evt, struct node *n);
void getSuccAndPredReply (Event evt, struct node *n);
int compare (const void * a, const void * b);
void stabilizeSuccessorListAuthenticate (Event evt, struct node *n);
unsigned int pred(unsigned int id);
void verifySuccessorListCorrectness();
int verifySuccessorListCorrectness(struct node* n, int pos);
// secure lookup
void secureLookup(Event evt, struct node *n);
void secureLookupRequest(Event evt, struct node *n);
void secureLookupReply(Event evt, struct node *n);
void secureLookupFixFinger(struct node *n, int lookupId);
// DHT level attacks
void performDHTLevelAttack();
unsigned int findClosestMaliciousNodeInLookup(unsigned int lookupId, unsigned int me);
void testDHTattack();
void runFixFingersSimulation();
void findNumberOfMaliciousNodesInFingerTables();
void printFingerTable();
void checkFingers();
void runFixFingersSimulationPart();
void printNodes();
void performMaliciousLookups();
void printFingerTable(unsigned int nodeId);

double prob_unreliability[7];
double path_count=0;

int max(int a,int b, int c){
  int ans=a;
  if(b>ans){
    ans=b;
  }
  if(c>ans){
    ans=c;
  }
  return ans;
}

int main(int argc, char *argv[]){

  // note that m should be close to log n, since the size of succ list should be 2*log n
  assert(pow(2,m)==MAXID);
  if(argc!=13){
    cout << "Usage: ./a.out num_nodes check_predecessor_timer stabilize_timer fix_fingers_timer sign_timer path_timer mean_alive simulation_time random_seed rLookup SINGLE_SUCCESSOR_IN_LIST ENABLE_DHT_LEVEL_ATTACK" << endl;
    exit(1);
  }
  num_nodes=atoi(argv[1]);
  check_predecessor_timer=atoi(argv[2]);
  stabilize_timer=atoi(argv[3]);
  fix_fingers_timer=atoi(argv[4]);
  guard_timer=max(check_predecessor_timer,stabilize_timer,fix_fingers_timer);
  sign_timer=atoi(argv[5]);
  path_timer=atoi(argv[6]);
  mean_alive=atoi(argv[7]);
  simulation_time=atoi(argv[8]);
  srand(atoi(argv[9]));
  rLookup = atoi(argv[10]);
  SINGLE_SUCCESSOR_IN_LIST = atoi(argv[11]);
  ENABLE_DHT_LEVEL_ATTACK = atoi(argv[12]);
  mean_alive_rate=1.0/(double)mean_alive;
	

  allnodes = new struct node[num_nodes];
  allnodesIds = new unsigned int[num_nodes];

  // lets initialize node state and the event queue 
  for(int i=0;i<num_nodes;i++){
    init(&allnodes[i]);
    map[allnodes[i].id]=i;
    allnodesIds[i] = allnodes[i].id;
  }
  qsort(allnodesIds, num_nodes, sizeof(unsigned int), compare);

  for(int i=0;i<num_nodes;i++){
    state_init_oracle(&allnodes[i]);
    assert(allnodes[i].alive==true);
  }
  performDHTLevelAttack();
  exit(0);

  /* // Perform the actions in the events queue */
  /* while(!FutureEventList.empty() && Clock < simulation_time ){ */
  /*   Event evt=FutureEventList.top(); */
  /*   FutureEventList.pop(); */
  /*   Clock=evt.get_time(); */
  /*   struct node * n; */

  /*   n=&allnodes[map[evt.get_id()]]; */

  /*   if(evt.get_id() != n->id) */
  /*     printf("%d %d %d %d\n", evt.get_id(), n->id, evt.get_type(), map[evt.get_id()]); */
  /*   assert(evt.get_id()==n->id); */
  /*   if(n->alive==0){ */
  /*     // the node is dead */
  /*     // two cases are interesting...that of the ping message, and node_alive */
  /*     // more interesting cases...get_pred and lookup */
  /*     if(evt.get_type()==Event::ping){ */
  /* 	// set up a dead message */
  /* 	struct msg message=evt.get_message(); */
  /* 	message.to=message.from; */
  /* 	message.from=n->id;	// this is not a real message but a simple way of initiating a timeout */
  /* 	Event evt2(Event::ping_timeout,Clock+TIMEOUT,message.to,message); */
  /* 	FutureEventList.push(evt2); */
  /*     } */
  /*     else if(evt.get_type()==Event::node_alive){ */
  /* 	node_alive(evt,n); */
  /*     } */
  /*     else if(evt.get_type()==Event::get_pred){ // this should make stabilization fault tolerant */
  /* 	// stabilize_timeout */
  /* 	/\* struct msg message=evt.get_message(); *\/ */
  /* 	/\* message.to=message.from; *\/ */
  /* 	/\* message.from=n->id; *\/ */
  /* 	/\* Event evt2(Event::stabilize_timeout, Clock+TIMEOUT,message.to,message); *\/ */
  /* 	/\* FutureEventList.push(evt2); *\/ */
  /*     } */
  /*     else if(evt.get_type()==Event::lookup){	// this should make lookups fault tolerant */
  /*     	// lookup_timeout ..but what if the destination of lookup_timeout is also dead..do we need to store the entire */
  /*     	// path of the lookup or what ? */
  /*     	// lets schedule a lookup_timeout */
  /*     	// we need to have a list of failed nodes in the path as well, to avoid them while backtracking */
  /*     	/\* struct msg message=evt.get_message(); *\/ */
  /*     	/\* message.failed_nodes.insert(message.to); *\/ */
  /*     	/\* if(!message.path.empty()){ *\/ */
  /*     	/\*   message.to=message.path.top(); *\/ */
  /*     	/\*   message.path.pop(); *\/ */
  /*     	/\*   Event evt2(Event::lookup,Clock+TIMEOUT,message.to,message); *\/ */
  /*     	/\*   FutureEventList.push(evt2); *\/ */
  /* 	cout<<"LOOKUP CALLED!!\n"; */
  /*     } */
  /*     else if(evt.get_type()==Event::secure_lookup){ */
  /* 	secureLookup(evt,n); */
  /*     } */
  /*   } */
  /*   else if(evt.get_type()==Event::lookup){ */
  /*     /\* lookup(evt,n); *\/ */
  /*     cout<<"LOOKUP CALLED!!\n"; */
  /*   } */
  /*   else if(evt.get_type()==Event::secure_lookup){ */
  /*     secureLookup(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::lookup_reply){ */
  /*     /\* lookup_reply(evt,n); *\/ */
  /*     cout<<"LOOKUP REPLY CALLED!!\n"; */
  /*   } */
  /*   else if(evt.get_type()==Event::secure_lookupReply){ */
  /*     secureLookupReply(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::ping){ */
  /*     ping(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::ping_reply){ */
  /*     ping_reply(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::get_pred){ */
  /*     get_pred(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::stabilize_reply){ */
  /*     stabilize_reply(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::stabilize_timeout){ */
  /*     stabilize_timeout(evt,n); */
  /*   }		 */
  /*   else if(evt.get_type()==Event::fix_fingers){ */
  /*     fix_fingers(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::notify){ */
  /*     notify(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::check_predecessor){ */
  /*     check_predecessor(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::ping_timeout){ */
  /*     ping_timeout(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::node_dead){ */
  /*     node_dead(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::sign_state){ */
  /*     sign_state(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::recv_sign){ */
  /*     recv_sign(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::initiate_path){ */
  /*     initiate_path(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::extend_path){ */
  /*     extend_path(evt,n); */
  /*   } */
  /*   else if(evt.get_type()==Event::authenticateReply){ */
  /*     authenticateReply(evt, n); */
  /*   } */
  /*   else if(evt.get_type()==Event::authenticateRequest){ */
  /*     authenticateRequest(evt, n); */
  /*   } */
  /*   else if(evt.get_type()==Event::getSuccAndPredRequest){ */
  /*     getSuccAndPredRequest(evt, n); */
  /*   } */
  /*   else if(evt.get_type()==Event::getSuccAndPredReply){ */
  /*     getSuccAndPredReply(evt, n); */
  /*   } */
  /*   if(!DISABLE_STABILIZE) */
  /*     { */
  /* 	if(evt.get_type()==Event::stabilizeSuccessorListRequest){ */
  /* 	  stabilizeSuccessorListRequest(evt, n); */
  /* 	} */
  /* 	else if(evt.get_type()==Event::stabilizeSuccessorList){ */
  /* 	  stabilizeSuccessorList(evt, n); */
  /* 	} */
  /* 	else if(evt.get_type()==Event::stabilizeSuccessorListAuthenticate){ */
  /* 	  stabilizeSuccessorListAuthenticate(evt, n); */
  /* 	} */
  /*     } */
  /* } */

  /* for(int i=0;i<7;i++){ */
  /*   cout << prob_unreliability[i]/path_count << " "; */
  /* } */
  /* cout << endl << endl;  */

  /* verifySuccessorListCorrectness(); */
  /* cout << endl << endl;  */
  /* // at the end of everything, lets check if most lookups succeed */
  /* int k=0; */
  /* for(int i=0;i<num_nodes;i++){ */
  /*   double correct_count6=0, correct_count8=0; */
  /*   double correct_count4=0; */
  /*   double correct_count2=0; */
  /*   double correct_count=0; */
  /*   double correct_count10=0,correct_count12=0; */
  /*   if(allnodes[i].alive==true){ */
			
  /*     if(allnodes[i].fingertable[0]==succ_alive(allnodes[i].id+1)){ */
  /* 	correct_count4++; */
  /*     } */

  /*     for(int j=1;j<2*m;j++){ */
  /* 	if(allnodes[i].fingertable[j]==succ_alive(allnodes[i].fingertable[j-1]+1)){ */
  /* 	  correct_count2++; */
  /* 	} */
  /*     } */

			
  /*     for(int j=2*m;j<3*m;j++){ */
  /* 	if(allnodes[i].fingertable[j]==succ_alive(allnodes[i].fingerid[j])){ */
  /* 	  correct_count++; */
  /* 	} */
  /* 	if(allnodes[i].fingertable_succ1[j]==succ_alive(allnodes[i].fingertable[j]+1)){ */
  /* 	  correct_count10++; */
  /* 	} */
  /* 	if(allnodes[i].fingertable_succ2[j]==succ_alive(allnodes[i].fingertable_succ1[j]+1)){ */
  /* 	  correct_count12++; */
  /* 	} */

  /* 	assert(allnodes[i].succ1.id==allnodes[i].fingertable[0]); */
  /* 	if(allnodes[i].succ1.fingertable[j]==succ_alive(allnodes[map[allnodes[i].fingertable[0]]].fingerid[j])){ */
  /* 	  correct_count6++; */
  /* 	} */
  /* 	assert(allnodes[i].succ2.id==allnodes[i].fingertable[1]); */
  /* 	if(allnodes[i].succ2.fingertable[j]==succ_alive(allnodes[map[allnodes[i].fingertable[1]]].fingerid[j])){ */
  /* 	  correct_count8++; */
  /* 	} */


  /*     } */
  /*     assert(correct_count10 <=m); */
  /*     cout << k << " " << correct_count4 << " " << correct_count2/(double)(2*m-1)  << " " << correct_count/(double)m << " " << correct_count6/(double)m << " "  */
  /* 	   << correct_count8/(double)m<< " " << correct_count10/(double)m <<  " " << correct_count12/(double)m << endl; */
  /*     k++; */

  /*   } */
  /* } */
  /* cout << "Number of nodes alive = " << idlist_alive.size() << endl; */
  /* cout << endl << endl;  */

  while(!FutureEventList.empty()){
    FutureEventList.pop();
  }
  /* runFixFingersSimulation(); */
  /* while(!FutureEventList.empty()){ */
  /*   FutureEventList.pop(); */
  /* } */
  // test malicious dht lookup code
  /* testDHTattack(); */
  /* exit(0); */

  priority_queue<Event> tempFutureEventList;
  int number_of_lookups = 10000;
  // create lookup requests
  for(int i=0;i<number_of_lookups;i++){	
    int random=rand()%num_nodes;
    while(allnodes[random].alive==false){
      random=rand()%num_nodes;
    }
    struct msg message;
    message.from=allnodes[random].id;
    message.to=message.from;
    message.value=rand()%MAXID;
    message.ttl=0;
    Event evt(Event::secure_lookup,Clock+2,message.to,message);
    tempFutureEventList.push(evt);
  }

  cout<<endl<<endl;
  unordered_map<int, double> successMap;
  // repeat for different % of malicious nodes f
  int f;
  cout<<"num nodes = "<<num_nodes<<" rLookup = "<<rLookup<<endl;
  for(f=20; f<=30; f+=1)
    {
      // reset counters
      num_count=0;
      num_ttl=0;
      num_new_lookup=0;
      // make all nodes non-malicious
      for(int i=0; i<num_nodes; i++)
	{
	  allnodes[i].iAmMalicious = 0;
	  allnodes[i].alreadyLookedUpList.clear();
	}
      // make %f nodes malicious
      int num_malicious_nodes = (f*num_nodes)/100;
      int count_malicious_nodes = 0;
      int random;
      while(count_malicious_nodes < num_malicious_nodes)
	{
	  random=rand()%num_nodes;
	  if(allnodes[random].iAmMalicious != 1)
	    {
	      allnodes[random].iAmMalicious = 1;
	      count_malicious_nodes++;
	      maliciousNodeList.insert(allnodes[random].id);
	    }
	}

      findNumberOfMaliciousNodesInFingerTables();
      if(ENABLE_DHT_LEVEL_ATTACK)
	{
	  cout<<"start\n";
	  runFixFingersSimulation();
	  while(!FutureEventList.empty()){
	    FutureEventList.pop();
	  }
	  cout<<"again\n";
	  runFixFingersSimulation();
	  while(!FutureEventList.empty()){
	    FutureEventList.pop();
	  }
	  cout<<"again\n";
	  runFixFingersSimulation();
	  while(!FutureEventList.empty()){
	    FutureEventList.pop();
	  }
	  cout<<"again\n";
	  runFixFingersSimulation();
	  while(!FutureEventList.empty()){
	    FutureEventList.pop();
	  }
	  cout<<"again\n";
	  runFixFingersSimulation();
	  while(!FutureEventList.empty()){
	    FutureEventList.pop();
	  }
	  cout<<"done\n";
	}
      findNumberOfMaliciousNodesInFingerTables();


      assert(FutureEventList.size()==0);
      // copy into future eventlist
      while(!tempFutureEventList.empty())
	{
	  Event evt = tempFutureEventList.top();
	  tempFutureEventList.pop();
	  FutureEventList.push(evt);
	}
      assert(FutureEventList.size()==(unsigned int)number_of_lookups);

      while(!FutureEventList.empty()){
	Event evt=FutureEventList.top();
	FutureEventList.pop();

	Clock=evt.get_time();
	struct node *n;
	n=&allnodes[map[evt.get_id()]];
	assert(evt.get_id()==n->id);
	if(evt.get_type()==Event::secure_lookup){
	  tempFutureEventList.push(evt);
	  secureLookup(evt,n);
	}
	else if(evt.get_type()==Event::secure_lookupRequest){
	  secureLookupRequest(evt,n);
	}
	else if(evt.get_type()==Event::secure_lookupReply){
	  secureLookupReply(evt,n);
	}
      }

      successMap[f] = (num_new_lookup/number_of_lookups)*100;
      cout << "f="<<f<<"% malicious nodes="<<num_malicious_nodes<<"/"<<num_nodes<<" success "<<successMap[f]<<endl;
    }

  /* cout << "Final time is " << Clock << endl; */

  cout<<"Final data"<<endl;

  for(f=0; f<=30; f+=1)
    cout<<"f="<<f<<"  "<<successMap[f]<<"% success"<<endl;
  cout<<endl<<endl;
  cout<<"plot data"<<endl<<endl;

  for(f=0; f<=30; f+=1)
    cout<<100.0-successMap[f]<<endl;
  cout<<endl;

  return 0;
}

/**
 * assign id to the node and set up the nodes initial vars
 */
void init(struct node *n){
  Clock=0;

  for(int i=0;i<7;i++){
    prob_unreliability[i]=0;
  }
  path_count=0;

  unsigned int id=rand()%MAXID; // in the real implementation use hash of the ip address
  while(idlist.find(id)!=idlist.end()){
    id=rand()%MAXID;
  }
  (*n).id=id;
  n->ipaddress = id; // let the ipaddress be the same as the id
  idlist.insert(id);
  idlist_alive.insert(id);
  for(int i=0;i<2*m;i++){
    (*n).fingerid[i]=n->id;
    (*n).predList[i]=n->id;
  }

  for(int i=2*m;i<3*m;i++){
    (*n).fingerid[i]=((*n).id+(unsigned int)pow(2,i-2*m))%MAXID;
  }
  n->next=2*m;
  n->alive=1;

  n->succ1.next=2*m;
  n->succ2.next=2*m;
}

/**
 * Set up the succ and succ1 lists for a node. Maintains shadow node information
 */
void state_init_oracle(struct node *n){
  n->fingertable[0]=succ(n->id+1);	// note that the fingertable is not strictly increasing. There is a sharp cut at 2m
  n->predList[0]=pred(n->id);

  for(int i=1;i<2*m;i++){
    n->fingertable[i]=succ(n->fingertable[i-1]+1);
    n->predList[i]=pred(n->predList[i-1]-1);
  }

  // lets create some randomness
  if (CREATE_RANDOMNESS)
    {
      for(int i=1, j = 0; i<2*m; i+=(rand()%4), j++){
	n->fingertable[j]=n->fingertable[i];
	n->predList[j]=n->predList[i];
      }
    }


  for(int i=2*m;i<3*m;i++){
    (*n).fingertable[i]=succ((*n).fingerid[i]);
    n->fingertable_succ1[i]=succ(n->fingertable[i]+1);	// lets maintain the shadows of the fingers
    n->fingertable_succ2[i]=succ(n->fingertable_succ1[i]+1);
  }
  // lets maintain nodes to whom i give the shadow certifications

  n->succ1.id=n->fingertable[0];
  n->succ2.id=n->fingertable[1];
  for(int i=2*m;i<3*m;i++){
    n->succ1.fingerid[i]=(n->succ1.id+(unsigned int)pow(2,i-2*m))%MAXID;
    n->succ1.fingertable[i]=succ(n->succ1.fingerid[i]);
    n->succ1.fingertable_succ1[i]=succ(n->succ1.fingertable[i]+1);
    n->succ1.fingertable_succ2[i]=succ(n->succ1.fingertable_succ1[i]+1);
			
    n->succ2.fingerid[i]=(n->succ2.id+(unsigned int)pow(2,i-2*m))%MAXID;
    n->succ2.fingertable[i]=succ(n->succ2.fingerid[i]);
    n->succ2.fingertable_succ1[i]=succ(n->succ2.fingertable[i]+1);
    n->succ2.fingertable_succ2[i]=succ(n->succ2.fingertable_succ1[i]+1);

  }

  set<unsigned int>::iterator iter;
  iter=idlist.find(n->id);
  if(iter==idlist.begin()){
    iter=idlist.end();
  }
  iter--;
  n->pred=*iter;
  assert(succ(*iter+1)==n->id);
	
  struct msg message;
  message.to=n->id;
  message.from=n->id;
	
  Event evt0(Event::sign_state,Clock+sign_timer,message.to,message);
  FutureEventList.push(evt0);
	
  Event evt1(Event::check_predecessor,Clock+check_predecessor_timer,message.to,message);
  FutureEventList.push(evt1);

  Event evt2(Event::stabilizeSuccessorListRequest,Clock+stabilize_timer,message.to,message);
  FutureEventList.push(evt2);
	
  Event evt3(Event::fix_fingers,Clock+fix_fingers_timer,message.to,message);
  FutureEventList.push(evt3);

  Event evt4(Event::node_dead,Clock+guard_timer+exponential_stream(mean_alive_rate),message.to,message);
  FutureEventList.push(evt4);

  Event evt5(Event::initiate_path,Clock+path_timer+sign_timer*2,message.to,message); // signed certificates should have been received
  FutureEventList.push(evt5);

}

/**
 *  Obtain the node closest to the given id in the network using Chord? Used to find the succ to a given node
 */
unsigned int succ(unsigned int id){		
  set<unsigned int>::iterator iter;
  iter=idlist.lower_bound(id);
  if(iter!=idlist.end()){
    return *iter;
  }
  else{
    return *idlist.begin();
  }
}

/**
 *  Obtain the node closest to the given id in the network using Chord? Used to find the pred to a given node
 */
unsigned int pred(unsigned int id){	
  set<unsigned int>::iterator iter;
  iter=idlist.lower_bound(id);
  if(iter!=idlist.begin()){
    iter--;
    return *iter;
  }
  else{
    return allnodesIds[num_nodes-1];
  }
}

unsigned int succ_alive(unsigned int id){		
  set<unsigned int>::iterator iter;
  iter=idlist_alive.lower_bound(id);		// need to maintain idlist_alive
  if(iter!=idlist_alive.end()){
    return *iter;
  }
  else{
    return *idlist_alive.begin();
  }
}

/**
 * Looking for a particular node or node closest to nodeId from the message in the evt. We use the Chord set up to look up a node.
 */
void lookup(Event evt, struct node *n){		// lookup will be recursive and will take time
  // the result of the lookup should be to schedule another lookup if you dont have the answer
  // if you have the answer, then directly send answer message to the initiator
	
  // first check if i can directly answer the query? 
  // for now i will only answer the query if i am the pred...maybe i can change this later to answer if x lies between fingerid and fingertable
  // schedule lookup_result message
  //
	
  /* unsigned int me=n->id; */
  /* assert(me==evt.get_id()); */
  /* struct msg message=evt.get_message(); */
	
  /* message.path.push(me); */
	
  /* message.ttl++; */
  /* if(message.ttl>100){ */
  /*   return;	// just drop the packet */
  /* } */
	
  /* // if looking for myself, i can just set up a lookup reply with my data. */
  /* if(message.value==me){ */
  /*   message.to=message.from; */
  /*   message.from=me; */
  /*   message.value2=me; */
  /*   message.value3=n->fingertable[0]; */
  /*   message.value4=n->fingertable[1]; */
  /*   Event evt2(Event::lookup_reply,Clock+1,message.to,message); */
  /*   FutureEventList.push(evt2); */
  /*   return; */

  /* } */
  /* // CHECK: return value if its in my succ list */
  /* // else find id closest to the id you are looking for in my fingertable data. */
  /* if(simCanon_NodeId_Closer(me,message.value,n->fingertable[0])==message.value){ */
  /*   message.to=message.from; */
  /*   message.from=me; */
  /*   message.value2=n->fingertable[0]; */
  /*   message.value3=n->fingertable[1]; */
  /*   message.value4=n->fingertable[2]; */
  /*   Event evt2(Event::lookup_reply,Clock+1,message.to,message); */
  /*   FutureEventList.push(evt2); */
  /*   return; */
  /* } */
  /* unsigned int next_hop=me; */
  /* for(int i=0;i<3*m;i++){	// avoid failed nodes */
  /*   if(simCanon_NodeId_Closer(next_hop,n->fingertable[i],message.value)==n->fingertable[i] &&  */
  /*      message.failed_nodes.find(n->fingertable[i])==message.failed_nodes.end()){ */
  /*     next_hop=n->fingertable[i]; */
  /*   } */
  /* } */
  /* // could not find it in my fingertable, so lets propogate the lookup to the next hop in my Chord lookup protocol */
  /* if(next_hop!=me){ */
  /*   message.to=next_hop; */
  /*   Event evt2(Event::lookup,Clock+1,message.to,message); */
  /*   FutureEventList.push(evt2);	 */
  /* } */
  /* else{	// all preceeding nodes have failed...pick the first alive succ in the succ list and thats the result */
  /*   //cout << me << " " << message.value << endl; */
  /*   //cout << n->fingertable[0] << " " << n->fingertable[1] << " " << succ_alive(message.value) ; */
  /*   //exit(1); */
  /*   // if none exists then lookup has failed */
  /* } */
  /* // check the closest fingertable entry to id */
  /* // schedule lookup message */
}

void lookup_reply(Event evt, struct node *n){
  /* // change old finger to point to the correct finger */
  /* // if i dont get this message, there is nothing to do */
	
  /* struct msg message=evt.get_message(); */
  /* num_count++; */
  /* num_ttl=num_ttl+message.ttl; */
  /* for(int i=2*m;i<3*m;i++){ */
  /*   if(n->fingerid[i]==message.value){ */
  /*     n->fingertable[i]=message.value2; */
  /*     n->fingertable_succ1[i]=message.value3; */
  /*     n->fingertable_succ2[i]=message.value4; */
  /*   } */
  /* } */
}

// called periodically
void fix_fingers(Event evt, struct node *n){	// periodically refresh fingers
  // only fix fingers after succ list!
  unsigned int me=n->id;
  assert(me==evt.get_id());

  // what we should do is only maintain fingers such that fingerid > fingertable[2*m-1].id
	
  n->fingertable[2*m]=n->fingertable[0];
  n->fingertable_succ1[2*m]=n->fingertable[1];
  n->fingertable_succ2[2*m]=n->fingertable[2];
  //  int breakpoint=3*m-1;

  for(int i=2*m+1;i<3*m;i++){
    if(simCanon_NodeId_Closer(me,n->fingerid[i],n->fingertable[0])==n->fingerid[i]){
      n->fingertable[i]=n->fingertable[0];
      n->fingertable_succ1[i]=n->fingertable[1];
      n->fingertable_succ2[i]=n->fingertable[2];
      continue;
    }
    for(int j=0;j<2*m-3;j++){
      if(simCanon_NodeId_Closer(n->fingertable[j],n->fingerid[i],n->fingertable[j+1])==n->fingerid[i]){
  	n->fingertable[i]=n->fingertable[j+1];
  	n->fingertable_succ1[i]=n->fingertable[j+2];
  	n->fingertable_succ2[i]=n->fingertable[j+3];
  	break;
      }
      if(j==2*m-2){
	//	breakpoint=i;
      }
    }
  }

  struct msg message;
  //  message.to = n->fingertable[n->next];			// use the lookup function already coded

  n->next=(n->next+1)%(3*m);
  /* if(n->next <2*m) */
  /*   n->next += 2*m; */

  /* if(n->next<breakpoint){ */
  /*   n->next=breakpoint; */
  /*   message.to=n->fingertable[breakpoint-1]; */
  /* } */
  message.value=n->fingerid[n->next];
  message.lookupId = n->next;

  /* if(n->id == 342391) */
  /*   cout<<"  "<<message.lookupId<<"  "<<message.value<<endl; */
  message.to = me;

  // send lookup msg to Rl nodes.
  message.ttl=0;
  message.path.push(me);	// always set ttl before issuing a lookup and add initiator to the path!
  message.from = message.to;
  assert(message.to == message.from);
  assert(message.value == n->fingerid[n->next]);

  Event evt2(Event::secure_lookup,Clock,message.to,message);
  FutureEventList.push(evt2);

  if(n->id == 342391)
    {
      //      cout<<" to = "<<message.to<<" message.value = "<<message.value<<" fingerid = "<<n->fingerid[message.lookupId]<<" n->id = "<<n->id<<endl;
    }

  // lets fix one each of  my succ1 and succ2's fingers

  /* breakpoint=3*m-1; */
  /* for(int i=2*m;i<3*m;i++){ */
  /*   for(int j=0;j<2*m-3;j++){ */
  /*     if(simCanon_NodeId_Closer(n->fingertable[j],n->succ1.fingerid[i],n->fingertable[j+1])==n->succ1.fingerid[i]){ */
  /* 	n->succ1.fingertable[i]=n->fingertable[j+1]; */
  /* 	n->succ1.fingertable_succ1[i]=n->fingertable[j+2]; */
  /* 	n->succ1.fingertable_succ2[i]=n->fingertable[j+3]; */
  /* 	break; */
  /*     } */
  /*     if(j==2*m-2){ */
  /* 	breakpoint=i; */
  /*     } */
  /*   } */
  /* } */

  /* struct msg message2; */
  /* message2.from=me; */
  /* //message2.to=n->succ1.fingertable[n->succ1.next]; */
  /* n->succ1.next=(n->succ1.next+1)%(3*m); */
  /* if(n->succ1.next < breakpoint){ */
  /*   n->succ1.next=breakpoint; */
  /*   //message2.to=n->succ1.fingertable[breakpoint-1]; */
  /* } */
  /* message2.value=n->succ1.fingerid[n->succ1.next]; */
  /* message2.ttl=0; */
  /* message2.path.push(me); */
  /* message2.to=me; */
  /* message2.lookupId = n->succ1.next; */
  /* message2.lookuptype = SUCC1; */
  /* Event evt3(Event::secure_lookup, Clock+1, message2.to,message2); */
  /* FutureEventList.push(evt3); */

  /* breakpoint=3*m-1; */
  /* for(int i=2*m;i<3*m;i++){ */
  /*   for(int j=0;j<2*m-3;j++){ */
  /*     if(simCanon_NodeId_Closer(n->fingertable[j],n->succ2.fingerid[i],n->fingertable[j+1])==n->succ2.fingerid[i]){ */
  /* 	n->succ2.fingertable[i]=n->fingertable[j+1]; */
  /* 	n->succ2.fingertable_succ1[i]=n->fingertable[j+2]; */
  /* 	n->succ2.fingertable_succ2[i]=n->fingertable[j+3]; */
  /* 	break; */
  /*     } */
  /*     if(j==2*m-2){ */
  /* 	breakpoint=i; */
  /*     } */
  /*   } */
  /* } */
  /* struct msg message3; */
  /* message3.from=me; */
  /* //message3.to=n->succ2.fingertable[n->succ2.next]; */
  /* n->succ2.next=(n->succ2.next+1)%(3*m); */
  /* if(n->succ2.next < breakpoint){ */
  /*   n->succ2.next=breakpoint; */
  /*   //message3.to=n->succ2.fingertable[breakpoint-1]; */
  /* } */
  /* message3.value=n->succ2.fingerid[n->succ2.next]; */
  /* message3.ttl=0; */
  /* message3.path.push(me); */
  /* message3.to=me; */
  /* message3.lookupId = n->succ2.next; */
  /* message3.lookuptype = SUCC2; */
  /* Event evt4(Event::secure_lookup, Clock+1, message3.to,message3); */
  /* FutureEventList.push(evt4); */

  // lets schedule fix_fingers again
  struct msg message5;
  message5.from=me;
  message5.to=me;
  Event evt5(Event::fix_fingers,Clock+fix_fingers_timer,message5.to,message5);	// earlier process should be over after 1000 time
  FutureEventList.push(evt5);
}

// what are we doing here? We do not seem to be doing anything important.
void  ping_reply(Event evt, struct node *n){
  unsigned int me=n->id;
  assert(me==evt.get_id());
  struct msg message=evt.get_message();
  //assert(n->pred==message.from);
}
// if a pred is dead, don't we want to lookup our new pred? 
void ping_timeout(Event evt, struct node *n){
  unsigned int me=n->id;
  assert(me==evt.get_id());
  n->pred=me;	// my predecessor is dead
}

void ping(Event evt, struct node *n){
  unsigned int me=n->id;
  assert(me==evt.get_id());
  struct msg message=evt.get_message();
  message.to=message.from;
  message.from=me;
  //cout << "scheduling a ping reply ";
  //cout << "Priority queue size is " << FutureEventList.size() << " " ;
  Event evt2(Event::ping_reply,Clock+1,message.to,message);
  FutureEventList.push(evt2);
  //cout << "Priority queue size is " << FutureEventList.size() << " " ;
}

// called periodically
void check_predecessor(Event evt, struct node *n){	// checks if the predecessor has failed
  // send ping message to predecessor
  unsigned int me=n->id;
  struct msg message;
  message.from=me;
  message.to=n->pred;
  //assert(message.to!=me);
  //cout << "scheduling one ping event " ;
  if(n->pred!=me){
    Event evt2(Event::ping,Clock+1,message.to,message);
    FutureEventList.push(evt2);
  }
  //cout << "Priority queue size is " << FutureEventList.size();
  message.from=me;
  message.to=me;
  Event evt3(Event::check_predecessor,Clock+check_predecessor_timer,message.to,message);
  FutureEventList.push(evt3);
  // set timeout event
  // if timeout event goes off, predecessor=nil
  // if receive ping reply, nullify timeout event
}

// event created by stabilize_reply
void notify(Event evt, struct node *n){	// i guess this is the action taken when the predecessor has failed
  // if predecessor is nil, or n' lies between predecessor,n
  // predecessor=n'
  unsigned int me=n->id;
  assert(me==evt.get_id());
  struct msg message=evt.get_message();
  if(n->pred==n->id){	// this means pred=nil
    n->pred=message.from;
  }
  else if(simCanon_NodeId_Closer(message.from,n->pred,me)==message.from){
    n->pred=message.from;
  }
  /* else if message.from lies between pred and me
     n->pred=message.from;
     }*/	
}

// called periodically
void stabilize(Event evt, struct node *n){	// key function to handle churn
  printf("CALLED STABLIZE!! SHOULD NOT HAPPEN ++++++++++++++++++++++++\n");
  unsigned int me=n->id;
  assert(me==evt.get_id());
  struct msg message;
  message.from=me;
  message.to=n->fingertable[0];
  Event evt2(Event::get_pred,Clock+1,message.to,message); // call get_pred on my immediate succ to stabilize
  FutureEventList.push(evt2);

  // call stabilize after intervals
  message.from=me;
  message.to=me;
  /* Event evt3(Event::stabilize,Clock+stabilize_timer,message.to,message); */
  /* FutureEventList.push(evt3); */
}

/**
 * Reply back to the stabilize request with the fingertable information.
 */
void get_pred(Event evt, struct node *n){
  unsigned int me=n->id;
  assert(me==evt.get_id());
  struct msg message=evt.get_message();
  message.to=message.from;
  message.from=me;
  message.value=n->pred;
  for(int i=0;i<2*m;i++){
    message.fingertable[i]=n->fingertable[i];	// here's my succ list
    message.predList[i]=n->predList[i];         // here's my pred list
  }
  Event evt2(Event::stabilize_reply,Clock+1,message.to,message);
  FutureEventList.push(evt2);	
}

/**
 * On receiving stabilize reply, we can use this information to update our fingertable, and notify our new immediate successor node.
 */
void stabilize_reply(Event evt, struct node *n){
  unsigned int me=n->id;
  assert(me==evt.get_id());
  struct msg message=evt.get_message();
  unsigned int x=message.value;
  // after making the stabilize request, the get_pred call replied with a node different from your own.
  // there is now a new node(s) between me and my pred. Update my fingertable accordingly
  if(x!=me && simCanon_NodeId_Closer(me,x,n->fingertable[0])==x){
    n->fingertable[0]=x;
    n->fingertable[1]=message.from;
    for(int i=2;i<2*m;i++){
      n->fingertable[i]=message.fingertable[i-2]; // copy fingertable returned by the node
    }
  }
  else{
    for(int i=1;i<2*m;i++){
      n->fingertable[i]=message.fingertable[i-1]; // copy fingertable returned by the node
    }
  }
  message.from=me;
  message.to=n->fingertable[0];
  Event evt2(Event::notify,Clock+1,message.to,message); // notify my  successor that I am its immediate predecessor
  FutureEventList.push(evt2);


  // now lets update the shadow nodes if needed
  if(n->fingertable[0]==n->succ1.id && n->fingertable[1]==n->succ2.id){
    // nothing to do
  }
  else if(n->fingertable[0]==n->succ2.id){
    // copy 2's data to 1...succ1 has failed
    n->succ1.id=n->succ2.id;
    n->succ2.id=n->fingertable[1];
    for(int i=2*m;i<3*m;i++){
      n->succ1.fingerid[i]=n->succ2.fingerid[i];
      n->succ1.fingertable[i]=n->succ2.fingertable[i];

      n->succ2.fingerid[i]=(n->succ2.id+(unsigned int)pow(2,i-2*m))%MAXID;
      // i need to build his tables
    }
    n->succ2.next=2*m;

		
  }
  else if(n->fingertable[1]==n->succ1.id){
    // new node added..copy 1 to w
    n->succ2.id=n->succ1.id;
    n->succ1.id=n->fingertable[0];
    for(int i=2*m;i<3*m;i++){
      n->succ2.fingerid[i]=n->succ1.fingerid[i];
      n->succ2.fingertable[i]=n->succ1.fingertable[i];

      n->succ1.fingerid[i]=(n->succ1.id+(unsigned int)pow(2,i-2*m))%MAXID;
      // i need to build his tables
    }
    n->succ1.next=2*m;

  }
  else{
    // 2 new nodes or both succ1/succ2 failed
    n->succ1.id=n->fingertable[0];
    n->succ2.id=n->fingertable[1];
    for(int i=2*m;i<3*m;i++){
      n->succ1.fingerid[i]=(n->succ1.id+(unsigned int)pow(2,i-2*m))%MAXID;
			
      n->succ2.fingerid[i]=(n->succ2.id+(unsigned int)pow(2,i-2*m))%MAXID;
      // i need to build both the tables
    }
    n->succ1.next=2*m;
    n->succ2.next=2*m;
  }
	
  // lets keep the old nodes fingers...they should be refreshed soon by fix fingers
  // actually for chord, the fingers would be quite similar
	
}

/**
 * if call to stabilize timed out. most probably becuase the pred died.
 */
void stabilize_timeout(Event evt, struct node *n){
  unsigned int me=n->id;
  assert(me==evt.get_id());
  struct msg message=evt.get_message(); // this means that my immediate succ is dead
	
  // restructure the succ list and reschedule get_pred
  //
  for(int i=0;i<2*m-1;i++){
    n->fingertable[i]=n->fingertable[i+1];
  }
  //assert(n->fingertable[0]==succ_alive(me+1));
  message.from=me;
  message.to=n->fingertable[0];
  Event evt2(Event::get_pred,Clock+1,message.to,message);
  FutureEventList.push(evt2);
}

unsigned int simCanon_NodeId_IncreasingDistance(unsigned int idsrc, unsigned int iddest) {
  // finds the distance to a point right before the iddest
  if (idsrc<iddest) {
    return iddest-idsrc;
  } else {
    // find distance across zero
    return (iddest-0)+(UINT_MAX-idsrc+1);
  }
}

/**
 * find nodeId closest to given id
 */
unsigned int simCanon_NodeId_Closer(unsigned int idsrc1, unsigned int idsrc2, unsigned int iddest) {

  if (simCanon_NodeId_IncreasingDistance(idsrc1,iddest)<simCanon_NodeId_IncreasingDistance(idsrc2,iddest))
    return idsrc1;
  else
    return idsrc2;
}

/**
 * set a node as dead if we get a node_dead message/event
 */
void node_dead(Event evt, struct node *n){
  unsigned int me=evt.get_id();
  assert(n->id==me);
  n->alive=0;	// remember that this node id is still in the idlist
  // note that this node should not immediately come back up again...will cause some problems ..
  idlist_alive.erase(n->id);
  struct msg message;
  message.from=me;
  message.to=me;
  Event evt2(Event::node_alive,Clock+guard_timer+exponential_stream(mean_alive_rate),message.to,message);
  FutureEventList.push(evt2);
}

/**
 * event created by node_dead from me to me
 */
void node_alive(Event evt, struct node *n){
  unsigned int me=evt.get_id();
  n->alive=1;
  assert(n->id==me);
		
  // initialize fingertable
  n->pred=me;
  // if he dies then i'm screwed...let me initialize the entire fingertable via an oracle
  n->fingertable[0]=succ_alive(n->id+1);
  for(int i=1;i<2*m;i++){
    n->fingertable[i]=succ_alive(n->fingertable[i-1]+1);
  }
  for(int i=2*m;i<3*m;i++){
    n->fingertable[i]=succ_alive(n->fingerid[i]);	
    n->fingertable_succ1[i]=succ_alive(n->fingertable[i]+1);	// lets maintain the shadows of the fingers
    n->fingertable_succ2[i]=succ_alive(n->fingertable_succ1[i]+1);

  }
	
  n->succ1.id=n->fingertable[0];
  n->succ2.id=n->fingertable[1];

  for(int i=2*m;i<3*m;i++){
    n->succ1.fingerid[i]=(n->succ1.id+(unsigned int)pow(2,i-2*m))%MAXID;
    n->succ1.fingertable[i]=succ_alive(n->succ1.fingerid[i]);
    n->succ1.fingertable_succ1[i]=succ_alive(n->succ1.fingertable[i]+1);
    n->succ1.fingertable_succ2[i]=succ_alive(n->succ1.fingertable_succ1[i]+1);
			
    n->succ2.fingerid[i]=(n->succ2.id+(unsigned int)pow(2,i-2*m))%MAXID;
    n->succ2.fingertable[i]=succ_alive(n->succ2.fingerid[i]);
    n->succ2.fingertable_succ1[i]=succ_alive(n->succ2.fingertable[i]+1);
    n->succ2.fingertable_succ2[i]=succ_alive(n->succ2.fingertable_succ1[i]+1);

  }
  idlist_alive.insert(me);
	
  // update others
  // updating is not done in the chord transactions paper...stabilization takes care of it	
	
  //schedule check_predecessor, fix_finger and stabilize, and node_dead
  struct msg message;
  message.from=me;
  message.to=me;

  Event evt0(Event::sign_state,Clock+sign_timer,message.to,message);
  FutureEventList.push(evt0);

  Event evt1(Event::check_predecessor,Clock+check_predecessor_timer,message.to,message);
  FutureEventList.push(evt1);

  Event evt2(Event::stabilizeSuccessorListRequest,Clock+stabilize_timer,message.to,message);
  FutureEventList.push(evt2);
	
  Event evt3(Event::fix_fingers,Clock+fix_fingers_timer,message.to,message);
  FutureEventList.push(evt3);
	
  Event evt4(Event::node_dead,Clock+guard_timer+exponential_stream(mean_alive_rate),message.to,message);
  FutureEventList.push(evt4);
	
  Event evt5(Event::initiate_path,Clock+path_timer+sign_timer*2,message.to,message); // signed certificates should have been received
  FutureEventList.push(evt5);

}

void sign_state(Event evt, struct node *n){

  unsigned int me=evt.get_id();
  struct msg message;
  message.from=me;
  message.to=n->fingertable[0];
  for(int i=2*m;i<3*m;i++){
    message.fingertable[i]=n->succ1.fingertable[i];
    message.fingertable_succ1[i]=n->succ1.fingertable_succ1[i];
    message.fingertable_succ2[i]=n->succ1.fingertable_succ2[i];
  }
  Event evt1(Event::recv_sign, Clock+1, message.to,message);
  FutureEventList.push(evt1);

  message.to=n->fingertable[1];
  for(int i=2*m;i<3*m;i++){
    message.fingertable[i]=n->succ2.fingertable[i];
    message.fingertable_succ1[i]=n->succ2.fingertable_succ1[i];
    message.fingertable_succ2[i]=n->succ2.fingertable_succ2[i];
  }

  Event evt2(Event::recv_sign, Clock+1, message.to,message);
  FutureEventList.push(evt2);

  message.to=n->id;
  Event evt3(Event::sign_state,Clock+sign_timer,message.to,message);
  FutureEventList.push(evt3);
}

void recv_sign(Event evt, struct node *n){

  struct msg message=evt.get_message();
  if(succ_alive(message.from+1)==n->id){
    n->pred=message.from;
    for(int i=2*m;i<3*m;i++){
      n->pred_fingertable[i]=message.fingertable[i];
      n->pred_fingertable_succ1[i]=message.fingertable_succ1[i];
      n->pred_fingertable_succ2[i]=message.fingertable_succ2[i];
    }
  }
  else if(succ_alive(succ_alive(message.from+1)+1)==n->id){
    n->pred1=message.from;	// hope this doesnt lead to oscillations! 
    for(int i=2*m;i<3*m;i++){
      n->pred1_fingertable[i]=message.fingertable[i];
      n->pred1_fingertable_succ1[i]=message.fingertable_succ1[i];
      n->pred1_fingertable_succ2[i]=message.fingertable_succ2[i];
    }
  }
}

/**
 * use the Map to create a path between two nodes?
 * we dont look at Event here?
 */
void initiate_path(Event evt, struct node *n){
  path_count++;	

  int random=rand()%m;
  unsigned int next_hop=n->fingertable[2*m+random];
  unsigned int next_hop_succ1=n->fingertable_succ1[2*m+random];	// damn the shadows are actually the predecessors!==> i need to know the node and its predecessors
  unsigned int next_hop_succ2=n->fingertable_succ2[2*m+random];

  unsigned int temp, temp1, temp2;
  // i can use a hack here...choose succ2 while making paths and verifying information from succ1 and fingertable node
  for(int i=0;i<7;i++){	// path length

    random=rand()%m;	
    temp=allnodes[map[next_hop_succ2]].fingertable[2*m+random];	
    temp1=allnodes[map[next_hop_succ2]].fingertable_succ1[2*m+random];
    temp2=allnodes[map[next_hop_succ2]].fingertable_succ2[2*m+random];

    if(allnodes[map[next_hop_succ2]].pred==next_hop_succ1 && allnodes[map[next_hop_succ2]].pred1==next_hop &&
       temp==allnodes[map[next_hop_succ2]].pred_fingertable[2*m+random] && temp==allnodes[map[next_hop_succ2]].pred1_fingertable[2*m+random] &&
       temp1==allnodes[map[next_hop_succ2]].pred_fingertable_succ1[2*m+random] && temp1==allnodes[map[next_hop_succ2]].pred1_fingertable_succ1[2*m+random] &&
       temp2==allnodes[map[next_hop_succ2]].pred_fingertable_succ2[2*m+random] && temp2==allnodes[map[next_hop_succ2]].pred1_fingertable_succ2[2*m+random]){
      // means evrything is good
      next_hop=temp;
      next_hop_succ1=temp1;
      next_hop_succ2=temp2;
    }
    else{
      for(int j=i;j<7;j++){	// note that j=0 refers to the first extend! therefore actual oath length = i+2
	prob_unreliability[j]++;
      }
      return;
    }
  }
}

void extend_path(Event evt, struct node *n){
  
}


double exponential_stream(double mean){
	
  double uniform, exponential;
  uniform =  (double) (1.0 * (rand() / (RAND_MAX + 1.0)));	
  exponential= ((-1/mean)*log(1-uniform));
  return exponential;
}


void debug(const char* s)
{
  if(DEBUG)
    {
      printf ("%s\n",s);
    }
}



/**************************
 * Start of Nandit's code *
 **************************/

unsigned int verifyNode = 3958;

/* Send stabilize request to nodes */
void stabilizeSuccessorListRequest(Event evt, struct node *n)
{
  unsigned int me=n->id;
  assert(me==evt.get_id());
  /* debug("stabilizeSuccessorListRequest"); */
  n->possibleSuccessors.clear(); // reset possibleSuccessors
  // Obtain the successorList and predecessorList of first rDHT nodes in the
  // current successor list

  // stabilize messages to successors and predecessors
  for (int i = 0; i < rDHT; ++i)
    {
      // successors
      n->possibleSuccessors.insert(n->fingertable[i]);
      struct msg message;
      message.from = n->id;
      message.to = n->fingertable[i];
      Event evt2(Event::getSuccAndPredRequest,Clock+1,message.to,message);
      FutureEventList.push(evt2);

      // predecessors
      n->possiblePred.insert(n->predList[i]); // holds predecessors 
      message.from = n->id;
      message.to = n->predList[i];
      Event evt3(Event::getSuccAndPredRequest,Clock+1,message.to,message);
      FutureEventList.push(evt3);
    }

  // stabilize the list after ~10 seconds
  struct msg message;
  message.from = n->id;
  message.to = n->id;

  Event evt2(Event::stabilizeSuccessorListAuthenticate,Clock+5,message.to,message);
  FutureEventList.push(evt2);
}

void getSuccAndPredRequest (Event evt, struct node *n)
{
  unsigned int me=n->id;
  assert(me==evt.get_id());
  /* debug("getSuccAndPredRequest"); */
  struct msg message=evt.get_message();
  message.to=message.from;
  message.from=me; // CHECK: make sure this is not garbage

  for(int i=0;i<2*m;i++){
    message.fingertable[i]=n->fingertable[i];	// here's my succ list
    message.predList[i]=n->predList[i];         // here's my pred list
  }

  Event evt2(Event::getSuccAndPredReply,Clock+1,message.to,message);
  FutureEventList.push(evt2);	
}

void getSuccAndPredReply (Event evt, struct node *n)
{
  unsigned int me=n->id;
  assert(me==evt.get_id());

  /* debug("getSuccAndPredReply"); */
  struct msg message=evt.get_message();
  // add content to possibleSuccessors and possiblePred

  for (unsigned int i=0; i < 2*m; ++i)
    {
      n->possibleSuccessors.insert( message.fingertable[i] );
      n->possiblePred.insert( message.predList[i] );
      if(idlist.find(message.predList[i]) == idlist.end())
	{
	  cout<<"fail "<<message.predList[i]<<"  "<<message.from<<" "<<n->id<<endl;
	}
      assert(idlist.find(message.predList[i]) != idlist.end());
      assert(idlist.find(message.fingertable[i]) != idlist.end());
    }
}

/* Called after timeout or after obtaining response from nodes */
void stabilizeSuccessorListAuthenticate (Event evt, struct node *n)
{
  unsigned int me=n->id;
  assert(me==evt.get_id());

  set<unsigned int>::iterator it;

  // auth succ
  for ( it = n->possibleSuccessors.begin() ; it != n->possibleSuccessors.end(); it++ )
    {
      if( *it > n->id )
	{
	  n->possibleSuccessorsStatus[*it] = WAITING;
	  authenticate( n->id, *it, *it );
	}
    }

  // auth pred
  for ( it = n->possiblePred.begin() ; it != n->possiblePred.end(); it++ )
    {
      if( *it > n->id )
	{
	  n->possiblePredStatus[*it] = WAITING;
	  authenticate( n->id, *it, *it );
	}
    }


  // sleep for ~10 seconds to get response from nodes
  struct msg message;
  message.to=n->id;
  message.from=n->id;
  Event evt2(Event::stabilizeSuccessorList,Clock+stabilize_timer,message.to,message);
  FutureEventList.push(evt2);
}

void stabilizeSuccessorList (Event evt, struct node *n)
{
  /* debug("stabilizeSuccessorList"); */
  // now that you have information form all nodes lets stabilize this thing
  // 2*m is the number of nodes we want in our successor list

  set<unsigned int>::iterator it;
  int count = 0;
  for ( it = n->possibleSuccessors.find(n->id)++, count=0 ; it != n->possibleSuccessors.end() && count<2*m; it++)
    {
      assert(idlist.find(*it) != idlist.end());

      if (  n->possibleSuccessorsStatus[*it] == AUTHENTICATED  && *it != n->id)
      	{
      	  // insert into my new succ list
      	  n->fingertable[count] = *it;
      	}
    }

  for ( it = n->possiblePred.find(n->id)--, count=0 ; it != n->possiblePred.begin() && count<2*m; it--)
    {
      assert(idlist.find(*it) != idlist.end());

      if (  n->possiblePredStatus[*it] == AUTHENTICATED  && *it != n->id)
      	{
      	  // insert into my new succ list
      	  n->predList[count] = *it;
      	  count++;
      	}
    }

  // create another stabilizeSuccessorListRequest after ~5 seconds
  struct msg message;
  message.to=n->id;
  message.from=n->id;
  Event evt2(Event::stabilizeSuccessorListRequest,Clock+stabilize_timer,message.to,message);
  FutureEventList.push(evt2);
}

void authenticate ( unsigned int from, unsigned int to, unsigned int toIP )
{
  /* debug("authenticate"); */
  // confirm that nodes IP address maps to nodes id
  if ( to != hashIP(toIP) )
    {
      cout<<to<<" != "<<hashIP(toIP);
      fprintf(stderr, "ERROR: THIS SHOULD NEVER HAPPEN. NODE->ID SHOULD BE SAME AS HASH FOR NOODE->IP");
      exit(0); // lets just crash here for now
    }

  // make a request to the node
  // lets create an event for this
  struct msg message;
  message.from = from;
  message.to = to;
  unsigned int seqNo = from + to; // for now just use this. later we can randmoize this.
  message.value = seqNo;
  Event evt2(Event::authenticateRequest, Clock+1, message.to, message);
  FutureEventList.push(evt2);
}

void authenticateRequest (Event evt, struct node *n)
{
  /* debug("authenticateRequest"); */
  // reply back saying that I am alive and well.
  struct msg message = evt.get_message();

  struct msg replyMessage;
  unsigned int seqNo = message.from + message.to; // for now just use this. later we can randmoize this.
  replyMessage.value = seqNo;
  replyMessage.from = n->id;
  replyMessage.to = message.from;

  Event evt2(Event::authenticateReply, Clock+1, replyMessage.to, replyMessage);
  FutureEventList.push(evt2);
}

void authenticateReply (Event evt, struct node *n)
{
  /* debug("authenticateReply"); */
  // verify that the seqNo is correct and then change status of node.
  struct msg message = evt.get_message();
  if ( message.value != n->id + message.from )
    {
      fprintf(stderr, "ERROR: SEQNO IS INCORRECT!");
      exit(0);
    }
  
  // update status of node
  n->possibleSuccessorsStatus[map[message.from]] = AUTHENTICATED;
}

// for now lets just return the ipaddress since we do not have a proper hashing function yet
unsigned int hashIP(unsigned int ipaddress)
{
  return ipaddress;
}


int compare (const void * a, const void * b)
{
  return ( *(int*)a - *(int*)b );
}


void verifySuccessorListCorrectness()
{
  /* cout<<"First node = "<<allnodesIds[0]<<"   Last node = "<<allnodesIds[num_nodes-1]<<endl; */
  /* int totalIncorrect = 0; */
  /* for (int i = 0; i < num_nodes; ++i) */
  /*   { */
  /*     struct node *n; */
  /*     n = &allnodes[map[allnodesIds[i]]]; */
  /*     // verifiy correctness of successor list of this node */

  /*     int incorrect = verifySuccessorListCorrectness(n, i); */
  /*     int valid = (2*m)-incorrect; */
  /*     cout<<n->id<<" "<<100*valid/(2*m)<<"%"<<" "<<valid<<" valid out of "<<2*m; */
  /*     if(idlist_alive.find(n->id) == idlist_alive.end()) */
  /* 	{ */
  /* 	  cout<<"  DEAD"; */
  /* 	} */
  /*     cout<<endl; */
  /*     totalIncorrect += incorrect; */
  /*   } */


  /* cout<<"Total Correct = "<<100*(num_nodes*2*m - totalIncorrect)/(num_nodes*2*m)<<"% "<< 2*m*num_nodes - totalIncorrect<<" valid out of "<<num_nodes*2*m<<endl; */
}

int verifySuccessorListCorrectness(struct node *n, int pos)
{
  // create the correct set of successor list for this node.
  int num = 0;
  int i = 0;
  set<unsigned int> expectedList;
  while(num<2*m)
    {
      struct node* temp = &allnodes[map[allnodesIds[(pos+i)%num_nodes]]];
      if (temp->alive && temp->id != n->id)
	{
	  expectedList.insert(temp->id);
	  num++;
	}
      i++;
    }

  // find intersection
  int incorrect = 0;
  set<unsigned int>::iterator it;
  for (i = 0; i < 2*m; ++i)
    {
      it = expectedList.find(n->fingertable[i]);
      if(it == expectedList.end())
	incorrect++;
    }

  /* if(verifyNode == n->id) */
  /*   { */
  /*     cout<<endl<<"expected result"<<endl; */
  /*     for ( it=expectedList.begin() ; it != expectedList.end(); it++ ) */
  /* 	{ */
  /* 	  cout<<"  "<<*it<<endl; */
  /* 	} */

  /*     cout<<endl; */
  /*     cout<<"my list"<<endl; */
  /*     for (i = 0; i < 2*m; i++) */
  /* 	{ */
  /* 	  cout<<"  "<<n->fingertable[i]<<endl; */
  /* 	}  */
  /*     cout<<endl; */
  /*   } */

  return incorrect;
}


/*******************
 *  Secure Lookup  *
 *******************/
unsigned int lookingFor = 342391;


void secureLookup(Event evt, struct node *n)
{
  // depending on rLookup send secure lookup request to that many nodes in your finger table.

  set<unsigned int> randomNodes;
  while( randomNodes.size() < (unsigned int)rLookup )
    {
      int nodeId = (2*m) + 1 + rand()%m;
      if(randomNodes.find(nodeId) == randomNodes.end())
  	{
  	  randomNodes.insert(nodeId);
  	}
    }

  /* randomNodes.clear(); */
  /* randomNodes.insert(2*m); */

  set<unsigned int>::iterator it;
  struct msg message=evt.get_message();

  assert(message.from == n->id);
  message.origin = n->id;

  for ( it = randomNodes.begin() ; it != randomNodes.end(); it++ )
    {
      message.to = n->fingertable[*it];

      Event evt2( Event::secure_lookupRequest,Clock+1,message.to,message);
      FutureEventList.push(evt2);
    }

}

void secureLookupRequest(Event evt, struct node *n)
{

  unsigned int me=n->id;
  assert(me==evt.get_id());
  struct msg message=evt.get_message();
  message.from = me;
  // I am an honest node
  message.path.push(me);
	
  // if looking for myself, i can just set up a lookup reply with my data.
  if(message.value==me){
    message.to=message.origin;
    message.from=me;
    message.value2=me;
    message.value3=n->fingertable[0];
    message.value4=n->fingertable[1];
    Event evt2(Event::secure_lookupReply,Clock+1,message.to,message);
    FutureEventList.push(evt2);
    return;

  }

  // I am a malicious node. Return closest malicious node to requested lookup id	
  if(n->iAmMalicious /*&& ENABLE_DHT_LEVEL_ATTACK && fixingFingersMode*/)
    {
      unsigned int maliciousNodeId = findClosestMaliciousNodeInLookup(message.value, me);
           /* cout<<"looking for "<<message.value<<" returning "<<maliciousNodeId<<" i am "<<me<<endl; */
      message.to=message.origin;
      message.from=me;
      node* maliciousNode = &allnodes[map[maliciousNodeId]];
      assert(maliciousNode->iAmMalicious == 1 );
      message.value2=maliciousNodeId;
      message.value3=maliciousNode->fingertable[1];
      message.value4=maliciousNode->fingertable[2];
      Event evt2(Event::secure_lookupReply,Clock+1,message.to,message);
      FutureEventList.push(evt2);
      return;
    } /*else if (n->iAmMalicious && !fixingFingersMode) // application level attack 
    {
      // drop packet
      return;
    }
      */


  // else find id closest to the id you are looking for in my fingertable data.
  if(simCanon_NodeId_Closer(me,message.value,n->fingertable[0])==message.value){
    message.to=message.origin;
    message.from=me;
    message.value2=n->fingertable[0];
    message.value3=n->fingertable[1];
    message.value4=n->fingertable[2];
    
    Event evt2(Event::secure_lookupReply,Clock+1,message.to,message);
    FutureEventList.push(evt2);
    return;
  }

  unsigned int next_hop=me;


  if (SINGLE_SUCCESSOR_IN_LIST)
    {
      if(simCanon_NodeId_Closer(next_hop,n->fingertable[0],message.value)==n->fingertable[0] &&
	 message.failed_nodes.find(n->fingertable[0])==message.failed_nodes.end()){
	next_hop=n->fingertable[0];
      }

      for(int i=(2*m);i<3*m;i++){	// avoid failed nodes
	if(simCanon_NodeId_Closer(next_hop,n->fingertable[i],message.value)==n->fingertable[i] &&
	   message.failed_nodes.find(n->fingertable[i])==message.failed_nodes.end()){
	  next_hop=n->fingertable[i];
	}
      }
    }
  else
    {
      // use entire successor list
      for(int i=0;i<3*m;i++){	// avoid failed nodes
	if(simCanon_NodeId_Closer(next_hop,n->fingertable[i],message.value)==n->fingertable[i] &&
	   message.failed_nodes.find(n->fingertable[i])==message.failed_nodes.end()){
	  next_hop=n->fingertable[i];
	}
      }
    }

  // could not find it in my fingertable, so lets propogate the lookup to the next hop in my Chord lookup protocol
  if(next_hop!=me){
    message.to=next_hop;
    Event evt2(Event::secure_lookupRequest,Clock+1,message.to,message);
    FutureEventList.push(evt2);	
  }
  else{	// all preceeding nodes have failed...pick the first alive succ in the succ list and thats the result
    //cout << me << " " << message.value << endl;
    //cout << n->fingertable[0] << " " << n->fingertable[1] << " " << succ_alive(message.value) ;
    //exit(1);
    // if none exists then lookup has failed
  }
  // check the closest fingertable entry to id
  // schedule lookup message
}

/**
 * On lookup reply check to see if the returned data is more 'accurate' than current data. If so, then replace, else forget.
 */
void secureLookupReply(Event evt, struct node *n)
{
  // add to the lookup request
  msg message=evt.get_message();

  (n->fixFingersSet).insert(message.value2);

  if((unsigned int)n->fixFingersSet.size()==(unsigned int)rLookup)
    {
      secureLookupFixFinger(n, message.lookupId);
      assert(n->fingerid[message.lookupId] == message.value);

      if(n->id == 342391)
	{
	  if(message.value2 == 342391)
	    {
	      /* cout<<message.value<<"  "<<message.value2<<"  "<<n->fingerid[message.lookupId]<<"  "<<n->fingertable[message.lookupId]<<"  "<<message.lookupId<<endl; */

	    }
	}
    }

}

void secureLookupFixFinger(struct node *n, int lookupId)
{
  unsigned int value = n->fingerid[lookupId];
  // pick the best one in the set
  set<unsigned int>::iterator it;
  for ( it = n->fixFingersSet.begin() ; it != n->fixFingersSet.end(); it++ )
    {
      if( (n->fingertable[lookupId] - value > *it - value) )
	{
	  n->fingertable[lookupId]=*it;
	}
    }

  n->fixFingersSet.clear();
}

/**
 * Used by a malicious node to return a malcious node closest to the id being looked up by a node.
 * This will result in a DHT level attack.
 * @return
 */
unsigned int findClosestMaliciousNodeInLookup(unsigned int lookupId, unsigned int me)
{
  /* // find the closest malicious node to the lookup Id requested. */
  /* set<unsigned int>::iterator it; */
  /* unsigned int closestMaliciousNode = *(maliciousNodeList.begin()); */

  /* if( lookupId < *(maliciousNodeList.begin()) ) */
  /*   { */
  /*     set<unsigned int>::iterator i = maliciousNodeList.end(); */
  /*     --i; */
  /*     closestMaliciousNode = *(i); */
  /*   } */
  /* else */
  /*   { */
  /*     for ( it=maliciousNodeList.begin() ; it != maliciousNodeList.end(); it++ ) */
  /* 	{ */
  /* 	  if(*it > closestMaliciousNode && *it < lookupId) */
  /* 	    { */
  /* 	      closestMaliciousNode = *it; */
  /* 	    } */
  /* 	} */
  /*   } */
  
  int tempId = lookupId;
  int id;
  do{
    id = succ(tempId);
    tempId = id + 1;
  }while(!allnodes[map[id]].iAmMalicious);
  assert(allnodes[map[id]].iAmMalicious == 1 );
  /* cout<<"looking for "<<lookupId<<" returning "<<id<<endl; */
  return id;//closestMaliciousNode;
}


/*****************************
 * testing DHT level attacks *
 *****************************/

void performDHTLevelAttack()
{
  int f = 20;

  // make all nodes non-malicious
  for(int i=0; i<num_nodes; i++)
    {
      allnodes[i].iAmMalicious = 0;
      allnodes[i].alreadyLookedUpList.clear();
    }
  // make %f nodes malicious
  int num_malicious_nodes = (f*num_nodes)/100;
  int count_malicious_nodes = 0;
  int random;

  while(count_malicious_nodes < num_malicious_nodes)
    {
      random=rand()%num_nodes;
      if(allnodes[random].iAmMalicious != 1)
	{
	  allnodes[random].iAmMalicious = 1;
	  count_malicious_nodes++;
	  maliciousNodeList.insert(allnodes[random].id);
	}
    }

  Clock = 0;
  for(int i=0; i<num_nodes; i++)
    {
      struct msg message;
      message.from = allnodes[i].id;
      message.to = message.from;
      Event evt(Event::fix_fingers,Clock,message.to,message);
      FutureEventList.push(evt);
    }

  runFixFingersSimulationPart();
}

void testDHTattack()
{
  int f = 10;

  // make all nodes good
  for(int i=0; i<num_nodes; i++)
    {
      allnodes[i].iAmMalicious = 0;
      allnodes[i].alreadyLookedUpList.clear();
    }
  // make %f nodes malicious
  int num_malicious_nodes = (f*num_nodes)/100;
  int count_malicious_nodes = 0;
  int random;
  while(count_malicious_nodes < num_malicious_nodes)
    {
      random=rand()%num_nodes;
      if(allnodes[random].iAmMalicious != 1)
	{
	  allnodes[random].iAmMalicious = 1;
	  count_malicious_nodes++;
	  maliciousNodeList.insert(allnodes[random].id);
	}
    }

  // print nodes
  printNodes();
  // perform malicious lookups
  performMaliciousLookups();
}

void performMaliciousLookups()
{
  int number_of_lookups = 10;

  for(int i=0;i<number_of_lookups;i++){	
    int random=rand()%num_nodes;
    while(allnodes[random].alive==false){
      random=rand()%num_nodes;
    }
    int from = allnodes[random].id;
    int lookupId= rand()%MAXID;
    int idReturned = findClosestMaliciousNodeInLookup(lookupId, from);

    cout<<"\n";
    cout<<"Id requested "<<lookupId;
    cout<<" By "<<from;
    cout<<" id returned "<<idReturned;
  }
  
}


void printNodes()
{
  set<unsigned int> nodeSet;
  unordered_map<unsigned int, int> node_M;

  for(int i=0;i<num_nodes;i++)
    {
      nodeSet.insert(allnodes[i].id);
      node_M[allnodes[i].id] = allnodes[i].iAmMalicious;
    }

  set<unsigned int>::iterator iter;

  cout<<"\nNode status\n\n";
  for(iter = nodeSet.begin(); iter!=nodeSet.end(); iter++)
    {
      cout<<"  "<<*iter;
      if(node_M[*iter])
	cout<<"  M";
      cout<<"\n";
    }
}
int highestMaliciousNodes = 0;
void runFixFingersSimulationPart()
{
  fixingFingersMode = 1;
  /* printNodes(); */
  /* printFingerTable(); */
  cout<<endl;
  int tempClock = Clock;
  findNumberOfMaliciousNodesInFingerTables();
  printFingerTable();

  while(1 /* originalClock+200 >= Clock */){

    Event evt=FutureEventList.top();
    FutureEventList.pop();
    Clock=evt.get_time();
    if(tempClock<Clock)
      {
	tempClock = Clock;
	/* findNumberOfMaliciousNodesInFingerTables(); */
	if(tempClock%1000==0){
	  printFingerTable();
	  findNumberOfMaliciousNodesInFingerTables();
	  /* exit(0); */
	}
      }
    struct node *n;
    n=&allnodes[map[evt.get_id()]];
    assert(evt.get_id()==n->id);
    if(evt.get_type()==Event::secure_lookup){
      secureLookup(evt,n);
    }
    else if(evt.get_type()==Event::secure_lookupRequest){
      secureLookupRequest(evt,n);
    }
    else if(evt.get_type()==Event::secure_lookupReply){
      secureLookupReply(evt,n);
    }
    else if(evt.get_type()==Event::fix_fingers){
      fix_fingers(evt,n);
    } 
  }

  /* printFingerTable(); */
  fixingFingersMode = 0; 
  /* exit(0); */

  while(!FutureEventList.empty()){
    FutureEventList.pop();
  }
}

void runFixFingersSimulation()
{
  findNumberOfMaliciousNodesInFingerTables();
  Clock = 0;
  for(int i=0; i<num_nodes/2; i++)
    {
      struct msg message;
      message.from = allnodes[i].id;
      message.to = message.from;
      Event evt(Event::fix_fingers,Clock,message.to,message);
      FutureEventList.push(evt);
    }
  runFixFingersSimulationPart();
  findNumberOfMaliciousNodesInFingerTables();
  Clock = 0;
  for(int i=num_nodes/2; i<num_nodes; i++)
    {
      struct msg message;
      message.from = allnodes[i].id;
      message.to = message.from;
      Event evt(Event::fix_fingers,Clock,message.to,message);
      FutureEventList.push(evt);
    }
  runFixFingersSimulationPart();
  findNumberOfMaliciousNodesInFingerTables();
}


void findNumberOfMaliciousNodesInFingerTables()
{
  int count = 0;
  for(int i=0; i<num_nodes; i++)
    {
      for(int j=2*m; j<3*m; j++)
	{
	  if ( allnodes[map[allnodes[i].fingertable[j]]].iAmMalicious )
	    count++;
	}

    }
  cout<<count<<"   "<<(double)(100*count)/(num_nodes*m)<<"%";

   if(highestMaliciousNodes < count)
     {
       highestMaliciousNodes = count;
       cout<<" *";
     }
   cout<<endl;
}

void printFingerTable(unsigned int nodeId)
{
  cout<<"finger table for"<<endl;
    for(int i=0; i<num_nodes; i++)
    {
      if(allnodes[i].id == nodeId)
	{
	  cout<<"** "<<allnodes[i].id;
	  if(allnodes[i].iAmMalicious)
	    cout<<"  M";
	  cout<<endl;
	  for(int j=2*m; j<3*m; j++)
	    {
	      assert(((int)pow(2,j-2*m)+allnodes[i].id)%MAXID == allnodes[i].fingerid[j]);
	      cout<<((int)pow(2,j-2*m)+allnodes[i].id)%MAXID<<" => "<<allnodes[i].fingertable[j];
	      if ( allnodes[map[allnodes[i].fingertable[j]]].iAmMalicious )
		cout<<" M";
	      cout<<endl;
	    }
	  break;
	}
    }
}

void printFingerTable()
{
  int random = rand()%num_nodes;
  printFingerTable(allnodes[random].id);
}

void checkFingers()
{
  cout<<"Fingers"<<endl;
  printNodes();

  for(int i=0; i<num_nodes; i++)
    {
      cout<<"** "<<allnodes[i].id<<endl;
      for(int j=2*m; j<3*m; j++)
	{
	  cout<<(int)pow(2,j-2*m)+allnodes[i].id<<" => "<<allnodes[i].fingertable[j];
	  if ( allnodes[map[allnodes[i].fingertable[j]]].iAmMalicious )
	    cout<<" M";
	  cout<<endl;
	}
      break;
    }

}
