/* Need to check that  simCanonNodeIdIncreasingDistance should be <= */
/* How does this change my results? */

#include"churn-simulator.h"

// my unit of time is in seconds
// node uptime uses pareto distribution 
// node downtime uses exponential distribution

// ok lets introduce some attackers baby

#ifdef simulation
#define maxnodes 1740
#endif


double TIMEOUT;	 

#ifdef simulation
double latency[maxnodes][maxnodes];
#endif

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


int bootstrap_count=0;
class node *allnodes; 
int num_nodes,check_predecessor_timer, stabilize_timer,fix_fingers_timer, guard_timer, simulation_time,mean_alive, sign_timer, path_timer,wait_timer;
double mean_alive_rate;
str bootstrap_server;
//#ifdef simulation
set<unsigned int> idlist,idlist_alive;
//unordered_map<unsigned int, int> map;
//#endif
double num_count=0, num_ttl=0;
void init(struct node *n);	// ok
void state_init_oracle(struct node *n);	// ok
unsigned int succ(unsigned int id);	// ok
unsigned int simCanon_NodeId_IncreasingDistance(unsigned int idsrc, unsigned int iddest);
unsigned int simCanon_NodeId_Closer(unsigned int idsrc1, unsigned int idsrc2, unsigned int iddest);
#ifdef simulation
void node_dead(Event evt, struct node *n);
void node_alive(Event evt, struct node *n);	
#endif
#ifdef simulation
double exponential_stream(double mean_rate);
double pareto_stream(double mean_rate);
#endif
unsigned int succ_alive(unsigned int id);
void serialize_send(int type, str dst_hostname, struct msg message);
//void send1(strbuf str, CLOSURE);
void deserialize_recv(strbuf);
void recv_msg(int sock_id,strbuf buf);
void accept_connection(int sock_id);
void start_node();
void verify();


set<unsigned int> global_list;
int recv_counter=0;
struct msg debug_message[50];

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

int num_start=0;



int main(int argc, char *argv[]){
	// note that m should be close to log n, since the size of succ list should be 2*log n
	assert(pow(2,m)==MAXID);
	if(argc!=13){
		cout << "Usage: ./a.out num_nodes check_predecessor_timer stabilize_timer fix_fingers_timer sign_timer path_timer mean_alive simulation_time timeout random_seed bootstrap_server wait_timer" << endl;
		exit(1);
	}
	async_init();
	
	#ifdef simulation
	num_nodes=atoi(argv[1]);
	assert(num_nodes <=maxnodes);
	#else
	num_nodes=1;
	#endif
	check_predecessor_timer=atoi(argv[2]);
	stabilize_timer=atoi(argv[3]);
	fix_fingers_timer=atoi(argv[4]);
	guard_timer=max(check_predecessor_timer,stabilize_timer,fix_fingers_timer);
	//guard_timer=0;
	sign_timer=atoi(argv[5]);
	path_timer=atoi(argv[6]);
	#ifdef simulation
	mean_alive=atoi(argv[7]);
	simulation_time=atoi(argv[8]);
	#endif
	srand(atoi(argv[10]));
	#ifdef simulation
	mean_alive_rate=1.0/(double)mean_alive;
	#endif
	bootstrap_server=argv[11];
	wait_timer=atoi(argv[12]);
	#ifdef simulation
	FILE *in;
	in=fopen("matrix","r");
	if(in==NULL){
		cout << "Could not open the topology file matrix" << endl;
		exit(1);
	}
	TIMEOUT=0;	
	for(int i=0;i<1740;i++){
		for(int j=0;j<1740;j++){
			fscanf(in,"%le ",&latency[i][j]);
			// my unit of time is in seconds
			latency[i][j]=latency[i][j]/2.0;// measurements correspond to RTT
			latency[i][j]=latency[i][j]/1000000.0; // measurements are in usec..need to convert to seconds
			if(latency[i][j]>TIMEOUT){
				TIMEOUT=latency[i][j];
			}
		}
	}
	fclose(in);
	#else
	TIMEOUT=atoi(argv[9]);
	#endif
	
	allnodes = new struct node[num_nodes];

	// lets initialize node state and the event queue 
	for(int i=0;i<num_nodes;i++){
		// NEED TO SET HOSTNAME somehow
		init(&allnodes[i]);
		#ifdef simulation	
		map[allnodes[i].id]=i;
		#endif
	}
	int sock_id=inetsocket(SOCK_STREAM,port);
	if(sock_id <0){
		fatal << "inetsocket\n"; 
	}
	make_async(sock_id);
	if(listen(sock_id,5) <0){
		fatal << "listen\n";
	}
	fdcb(sock_id,selread,wrap(accept_connection,sock_id));		

	if(bootstrap_server=="manager"){
		// i am the manager and will kick start the experiment
		start_node();
	}
	else{
		for(int i=0;i<num_nodes;i++){
			state_init_oracle(&allnodes[i]);	// we need to make this function distributed! 
			#ifdef simulation
			assert(allnodes[i].alive==true);
			#endif
		}
	}
	amain();
	return 0;
}

void start_node(){
	if(num_start <=49){
		char command[500];
		sprintf(command,"ssh -o \"StrictHostKeyChecking no\" mittal2@node%d.shadowwalker.uiucnet.emulab.net \"nohup /proj/uiucnet/mittal2/shadowwalker-implementation/churn-simulator 1 1 1 1 1 1 1 1 2 %d node0.shadowwalker.uiucnet.emulab.net 5 \" &",num_start,num_start*10);
		warn <<"STARTING NODE " << num_start << "\n";
		system(command);
		if(num_start !=49){
			delaycb(10,0,wrap(start_node));
		}
		else{ // num_start ==50
			delaycb(120,0,wrap(start_node));

		}
		num_start++;
	}
	else{
		// here we can send debug_state messages 
		// once we collect all the messages, we can verify the topology
		struct msg message;
		str dst_hostname;
		char char_dst_hostname[100];
		message.from=allnodes[0].id;
		warn <<"REQUESTING DEBUG MESSAGES\n";
		for(int i=0;i<=49;i++){
			sprintf(char_dst_hostname,"node%d.shadowwalker.uiucnet.emulab.net",i);
			dst_hostname=char_dst_hostname;
			serialize_send(debug_state_msg,dst_hostname,message);		
		}
		delaycb(20,0,wrap(verify)); 	// wait 20 seconds and then call verify! 
	}
}
  
void accept_connection(int sock_id){
	
	struct sockaddr_in sin;
	unsigned sinlen=sizeof(sin);
	int cs=accept(sock_id,(struct sockaddr *)&sin,&sinlen);
	strbuf buf;
	if(cs < 0){
		//warn << "problem with accept_connection\n";
		
	}
	else{
		//warn << "connection accepted : " << "socket descriptor = :" << cs << "\n";
	//	warn << "Calling recv message now \n";
		//recv_msg(cs);
		fdcb(cs,selread,wrap(recv_msg,cs,buf));
	}
}


void init(struct node *n){
	for(int i=0;i<7;i++){
		prob_unreliability[i]=0;
	}
	path_count=0;

	unsigned int id=rand()%MAXID;
	#ifdef simulation
	while(idlist.find(id)!=idlist.end()){
		id=rand()%MAXID;
	}
	#endif
	(*n).id=id;
	//panic << id;
	#ifdef simulation
	idlist.insert(id);
	idlist_alive.insert(id);
	#endif
	// succ list
	for(int i=0;i<2*m;i++){
		(*n).fingerid[i]=n->id;
	}
	// finger table nodes
	for(int i=2*m;i<3*m;i++){
		(*n).fingerid[i]=((*n).id+(unsigned int)pow(2,i-2*m))%MAXID;
	}
	n->next=2*m;
	#ifdef simulation
	n->alive=1;
	#endif

	n->succ1.next=2*m; // shadows
	n->succ2.next=2*m; // shadows
	char hostname[1024];
	if(gethostname(hostname,1024)==0){
		n->hostname=hostname;
	}
	else{
		fatal << "Could not get hostname\n"; 
	}
}

void state_init_oracle(struct node *n){
	if(n->hostname==bootstrap_server){ // I am the bootstrap server
		n->fingertable[0]=n->id;
		n->hostnametable[0]=n->hostname;
		for(int i=1;i<2*m;i++){
			n->fingertable[i]=n->id;
			n->hostnametable[i]=n->hostname;
		}
		for(int i=2*m;i<3*m;i++){
			n->fingertable[i]=n->id;
			n->hostnametable[i]=n->hostname;
			n->fingertable_succ1[i]=n->id;
			n->hostnametable_succ1[i]=n->hostname;
			n->fingertable_succ2[i]=n->id;
			n->hostnametable_succ2[i]=n->hostname;
		}
		n->succ1.id=n->id;
		n->succ2.id=n->id;
		for(int i=2*m;i<3*m;i++){
			n->succ1.fingerid[i]=(n->succ1.id+(unsigned int)pow(2,i-2*m))%MAXID;
			n->succ1.fingertable[i]=n->id;
			n->succ1.hostnametable[i]=n->hostname;
			n->succ1.fingertable_succ1[i]=n->id;
			n->succ1.hostnametable_succ1[i]=n->hostname;
			n->succ1.fingertable_succ2[i]=n->id;
			n->succ1.hostnametable_succ2[i]=n->hostname;
			
			n->succ2.fingerid[i]=(n->succ2.id+(unsigned int)pow(2,i-2*m))%MAXID;
			n->succ2.fingertable[i]=n->id;
			n->succ2.hostnametable[i]=n->hostname;
			n->succ2.fingertable_succ1[i]=n->id;
			n->succ2.hostnametable_succ1[i]=n->hostname;
			n->succ2.fingertable_succ2[i]=n->id;
			n->succ2.hostnametable_succ2[i]=n->hostname;

		}

		n->pred=n->id;
		n->hostname_pred=n->hostname;
		delaycb(wait_timer+sign_timer,0,wrap(n,&node::sign_state));
		delaycb(wait_timer+check_predecessor_timer,0,wrap(n,&node::check_predecessor));
		delaycb(wait_timer+stabilize_timer,0,wrap(n,&node::stabilize));
		delaycb(wait_timer+fix_fingers_timer,0,wrap(n,&node::fix_fingers));
		// delay_cb(path_timer+sign_timer*2,0,wrap(initiate_path));	// interface with Tor path controller written in Python
		
		#ifdef simulation
		delaycb(wait_timer+guard_timer+pareto_stream(mean_alive_rate),0,wrap(node_dead));
		#endif

	
	}
	else{	// get information from the bootstrap server
		// send a bootstrap message (id) to the bootstrap server 
		// recv the server's response containing your state
		// this is the only code left to write - wohooooo! 
		// note: bootstrap server only sends in my successor list! 
		// i can then build my remain state using lookups
		for(int i=0;i<3*m;i++){
			n->fingertable[i]=n->id;
			n->hostnametable[i]=n->hostname;
		}
		struct msg message;
		message.from=n->id; 
		message.original_from=n->id;
		message.hostname_original_from=n->hostname;
		message.ttl=0;
		message.path.push(n->id);
		message.value=n->id;
		serialize_send(lookup_msg,bootstrap_server,message);
	}
}

void state_init_oracle2(struct node *n, struct msg recv_message){

	
	struct msg message=recv_message;
	n->fingertable[0]=message.value2;
	n->hostnametable[0]=message.hostname_value2;
	n->fingertable[1]=message.value3;
	n->hostnametable[1]=message.hostname_value3;
	//warn << "The succ values are : " << message.value2 << " " << message.hostname_value2 << " " << message.value3 << " " << message.hostname_value3 <<"\n";
	//exit(1);
	/*n->fingertable[0]=message.fingertable[0];	// note that the fingertable is not strictly increasing. There is a sharp cut at 2m
	n->hostnametable[0]=message.hostnametable[0];*/
		
		/*for(int i=1;i<2*m;i++){
			n->fingertable[i]=message.fingertable[i];
			n->hostnametable[i]=message.hostnametable[i];
		}*/
		/*for(int i=2*m;i<3*m;i++){
			n->fingertable[i]=message.fingertable[i];
			n->hostnametable[i]=message.hostnametable[i];
			n->fingertable_succ1[i]=message.fingertable_succ1[i];	// lets maintain the shadows of the fingers
			n->hostnametable_succ1[i]=message.hostnametable_succ1[i];
			n->fingertable_succ2[i]=message.fingertable_succ2[i];
			n->hostnametable_succ2[i]=message.hostnametable_succ2[i];
		}*/
		// lets maintain nodes to whom i give the shadow certifications
	
		
	n->succ1.id=n->fingertable[0];
	n->succ2.id=n->fingertable[1];
	for(int i=2*m;i<3*m;i++){
		n->succ1.fingerid[i]=(n->succ1.id+(unsigned int)pow(2,i-2*m))%MAXID;
	//		n->succ1.fingertable[i]=succ(n->succ1.fingerid[i]);
	//		n->succ1.fingertable_succ1[i]=succ(n->succ1.fingertable[i]+1);
	//		n->succ1.fingertable_succ2[i]=succ(n->succ1.fingertable_succ1[i]+1);
				
		n->succ2.fingerid[i]=(n->succ2.id+(unsigned int)pow(2,i-2*m))%MAXID;
	//		n->succ2.fingertable[i]=succ(n->succ2.fingerid[i]);
	//		n->succ2.fingertable_succ1[i]=succ(n->succ2.fingertable[i]+1);
	//		n->succ2.fingertable_succ2[i]=succ(n->succ2.fingertable_succ1[i]+1);
	
	}
		// let us build this node's remaining state
	message.from=n->id;
	message.original_from=n->id;
	message.hostname_original_from=n->hostname;
	message.to=n->id;
	message.ttl=0;
	message.path.push(n->id);
	for(int i=2*m;i<3*m;i++){
		message.value=n->fingerid[i];
		serialize_send(lookup_msg,n->hostname,message);
		message.value=n->succ1.fingerid[i];
		serialize_send(lookup_msg,n->hostname,message);
		message.value=n->succ2.fingerid[i];
		serialize_send(lookup_msg,n->hostname,message);
	}
	//set<unsigned int>::iterator iter;
	//iter=idlist.find(n->id);
	//if(iter==idlist.begin()){
	//	iter=idlist.end();
	//}
		//iter--;
		//  n->pred=*iter;
		//assert(succ(*iter+1)==n->id);
	if(n->fingertable[0]!=n->fingertable[1]){ // atleast 2 nodes
		// stabilization functions should take care of this
		n->pred=n->id;
		n->hostname_pred=n->hostname;
	}
	else{
		n->pred=n->fingertable[0];
		n->hostname_pred=n->hostnametable[0];
	}
	
	int wait_timer=5;
	delaycb(wait_timer+sign_timer,0,wrap(n,&node::sign_state));
	delaycb(wait_timer+check_predecessor_timer,0,wrap(n,&node::check_predecessor));
	delaycb(wait_timer+stabilize_timer,0,wrap(n,&node::stabilize));
	delaycb(wait_timer+fix_fingers_timer,0,wrap(n,&node::fix_fingers));
	// delay_cb(path_timer+sign_timer*2,0,wrap(initiate_path));	// interface with Tor path controller written in Python
	
	#ifdef simulation
	delaycb(wait_timer+guard_timer+pareto_stream(mean_alive_rate),0,wrap(node_dead));
	#endif
}

/*void node::bootstrap(struct msg recv_message){
	//unsigned int me=this->id;
	// bootstrap_get_pred behaves like the lookup message but replies with the succ list of the chosen id
	// should be sent to myself
	//struct msg
	serialize_send(bootstrap_get_pred_msg,this->hostname,msg); 
}*/

unsigned int succ(unsigned int id){		// where do we use this: perhaps, lookup will suffice
	set<unsigned int>::iterator iter;
	/*for(iter=idlist.begin();iter!=idlist.end();iter++){
		if(*iter >= id){		// should this be >=
			return *iter;
		}
	}*/
	iter=global_list.lower_bound(id);
	if(iter!=global_list.end()){
		return *iter;
	}
	else{
		return *global_list.begin();
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


void node::debug_state(struct msg recv_message){
	struct msg message;
	message.from=this->id;
	message.to=recv_message.from;
	for(int i=0;i<2*m;i++){
		message.fingertable[i]=this->fingertable[i];
	}
	for(int i=2*m;i<3*m;i++){
		message.fingertable[i]=this->fingertable[i];
		message.fingertable_succ1[i]=this->fingertable_succ1[i];
		message.fingertable_succ2[i]=this->fingertable_succ2[i];
	}
	serialize_send(debug_state_reply_msg,recv_message.hostname_from,message);
}

void node::debug_state_reply(struct msg recv_message){

	global_list.insert(recv_message.from);
	debug_message[recv_counter]=recv_message;
	recv_counter++;
}


void verify(){
	char command[500];
	warn << "Received reply from " << global_list.size() << "nodes\n";
	set<unsigned int>::iterator iter;
	for(iter=global_list.begin();iter!=global_list.end();iter++){
		warn << *iter << " " ;
	}
	warn << "\n\n";
	for(int i=0;i<=49;i++){
		warn << "Node : " << debug_message[i].from << "\n";
		unsigned int next=succ(debug_message[i].from+1)%MAXID;
		for(int j=0;j<2*m;j++){
			warn << debug_message[i].fingertable[j] << ":" << next << " ";
			next=succ((next+1)%MAXID);
		}
		warn <<"\n";
		for(int j=2*m;j<3*m;j++){
			unsigned int should_be=succ((debug_message[i].from+(unsigned int)pow(2,(j-2*m)))%MAXID);
			if(debug_message[i].fingertable[j]==succ((debug_message[i].from+(unsigned int)pow(2,(j-2*m)))%MAXID)){	// fingertable entry is correct
				//warn << "1 ";
			}
			else{		// fingertable entry is incorrect
				//warn << "0 ";
			}
			warn << debug_message[i].fingertable[j] << ":" << should_be << " ";
		}
		warn << "\n\n";
		sprintf(command,"ssh -o \"StrictHostKeyChecking no\" mittal2@node%d.shadowwalker.uiucnet.emulab.net \"pkill churn-simulator\" &",i);
		warn << "Killing process on node " << i << "\n";
		system(command);

	}
	exit(0);
}

void node::lookup(struct msg recv_message){		// lookup will be recursive and will take time
	// the result of the lookup should be to schedule another lookup if you dont have the answer
	// if you have the answer, then directly send answer message to the initiator
	
	// first check if i can directly answer the query? 
	// for now i will only answer the query if i am the pred...maybe i can change this later to answer if x lies between fingerid and fingertable
	// schedule lookup_result message
	//
	
	unsigned int me=this->id;
	struct msg message=recv_message;
	
	message.path.push(me);
	
	message.ttl++;
	if(message.ttl>100){
		return;	// just drop the packet
	}
	
	if(message.value==me){
		// return me
		message.to=message.original_from;
		message.from=me;
		//message.hostname_from=this->hostname;
		message.value2=me;
		message.hostname_value2=this->hostname;
		message.value3=this->fingertable[0];
		message.hostname_value3=this->hostnametable[0];
		message.value4=this->fingertable[1];
		message.hostname_value4=this->hostnametable[1];
		serialize_send(lookup_reply_msg,message.hostname_original_from,message);
		//Event evt2(Event::lookup_reply,Clock+latency[map[me]][map[message.to]],message.to,message);
		//FutureEventList.push(evt2);
		//assert(message.value2==succ(message.value));
		return;

	}
	if(me==this->fingertable[0]){ // i am the only node in the system
		// return me
		message.to=message.original_from;
		message.from=me;
		//message.hostname_from=this->hostname;
		message.value2=me;
		message.hostname_value2=this->hostname;
		message.value3=this->fingertable[0];
		message.hostname_value3=this->hostnametable[0];
		message.value4=this->fingertable[1];
		message.hostname_value4=this->hostnametable[1];
		serialize_send(lookup_reply_msg,message.hostname_original_from,message);
		//Event evt2(Event::lookup_reply,Clock+latency[map[me]][map[message.to]],message.to,message);
		//FutureEventList.push(evt2);
		//assert(message.value2==succ(message.value));
		return;

	}

	if(simCanon_NodeId_Closer(me,message.value,this->fingertable[0])==message.value){
	
		//assert(n->fingertable[0]==succ(message.value));
		message.to=message.original_from;
		message.from=me;
		//message.hostname_from=this->hostname;
		message.value2=this->fingertable[0];
		message.hostname_value2=this->hostnametable[0];
		message.value3=this->fingertable[1];
		message.hostname_value3=this->hostnametable[1];
		message.value4=this->fingertable[2];
		message.hostname_value4=this->hostnametable[2];
		serialize_send(lookup_reply_msg,message.hostname_original_from,message);
		//Event evt2(Event::lookup_reply,Clock+latency[map[me]][map[message.to]],message.to,message);
		//FutureEventList.push(evt2);
		//assert(message.value2==succ(message.value));
		return;
	}
	unsigned int next_hop=me;
	str hostname_next_hop=this->hostname;
	for(int i=0;i<3*m;i++){	// avoid failed nodes
		if(simCanon_NodeId_Closer(next_hop,this->fingertable[i],message.value)==this->fingertable[i] && 
		   message.failed_nodes.find(this->fingertable[i])==message.failed_nodes.end()){
			next_hop=this->fingertable[i];
			hostname_next_hop=this->hostnametable[i];
		}
	}

	//assert(next_hop!=me); 	==> all precedding hops have failed
	if(next_hop!=me){
		message.to=next_hop;
		message.from=me; // note that we have not changed the original form field! 
		serialize_send(lookup_msg,hostname_next_hop,message);
		//Event evt2(Event::lookup,Clock+latency[map[me]][map[message.to]],message.to,message);
		//FutureEventList.push(evt2);	
	}
	else{	// all preceeding nodes have failed...pick the first alive succ in the succ list and thats the result
		//cout << me << " " << message.value << endl;
		//cout << n->fingertable[0] << " " << n->fingertable[1] << " " << succ_alive(message.value) ;
		//exit(1);
		// if none exists then lookup has failed
	//	panic << "I am here";
	}
	// check the closest fingertable entry to id
	// schedule lookup message
}

void node::lookup_reply(struct msg recv_message){
	// change old finger to point to the correct finger
	// if i dont get this message, there is nothing to do
		
	struct msg message=recv_message;
	if(message.value==this->id){	// bootstrap reply
		if(bootstrap_count==1){
			panic << "Multiple bootstrap! " ;
		}
		//warn << "Received bootstrap reply\n";
		state_init_oracle2(&allnodes[0],recv_message);
		bootstrap_count++;
		return;
	}
	
	
	num_count++;
	num_ttl=num_ttl+message.ttl;
	for(int i=2*m;i<3*m;i++){
		if(this->fingerid[i]==message.value){
			//assert(message.value2==succ(message.value));
			//assert(message.value2==n->fingertable[i]);	// remove this assertion when handling churn
			this->fingertable[i]=message.value2;
			this->hostnametable[i]=message.hostname_value2;
			this->fingertable_succ1[i]=message.value3;
			this->hostnametable_succ1[i]=message.hostname_value3;
			this->fingertable_succ2[i]=message.value4;
			this->hostnametable_succ2[i]=message.hostname_value4;
			//cout << message.value2 << " " << message.value3 << " " << message.value4 << endl;
			//break;	//this should fix things
		}
		if(this->succ1.fingerid[i]==message.value){
			this->succ1.fingertable[i]=message.value2;
			this->succ1.hostnametable[i]=message.hostname_value2;
			this->succ1.fingertable_succ1[i]=message.value3;
			this->succ1.hostnametable_succ1[i]=message.hostname_value3;
			this->succ1.fingertable_succ2[i]=message.value4;
			this->succ1.hostnametable_succ2[i]=message.hostname_value4;
		}

		if(this->succ2.fingerid[i]==message.value){
			this->succ2.fingertable[i]=message.value2;
			this->succ2.hostnametable[i]=message.hostname_value2;
			this->succ2.fingertable_succ1[i]=message.value3;
			this->succ2.hostnametable_succ1[i]=message.hostname_value3;
			this->succ2.fingertable_succ2[i]=message.value4;
			this->succ2.hostnametable_succ2[i]=message.hostname_value4;

		}
	}
	for(int i=2*m;i<3*m;i++){
		if(simCanon_NodeId_Closer(message.value, this->fingerid[i], message.value2)==this->fingerid[i]){
			this->fingertable[i]=message.value2;
			this->hostnametable[i]=message.hostname_value2;	
			this->fingertable_succ1[i]=message.value3;
			this->hostnametable_succ1[i]=message.hostname_value3;	
			this->fingertable_succ2[i]=message.value4;
			this->hostnametable_succ2[i]=message.hostname_value4;	
		}
		if(simCanon_NodeId_Closer(message.value, this->succ1.fingerid[i], message.value2)==this->succ1.fingerid[i]){
			this->succ1.fingertable[i]=message.value2;
			this->succ1.hostnametable[i]=message.hostname_value2;
			this->succ1.fingertable_succ1[i]=message.value3;
			this->succ1.hostnametable_succ1[i]=message.hostname_value3;
			this->succ1.fingertable_succ2[i]=message.value4;
			this->succ1.hostnametable_succ2[i]=message.hostname_value4;
		}
		if(simCanon_NodeId_Closer(message.value, this->succ2.fingerid[i], message.value2)==this->succ2.fingerid[i]){
			this->succ2.fingertable[i]=message.value2;
			this->succ2.hostnametable[i]=message.hostname_value2;
			this->succ2.fingertable_succ1[i]=message.value3;
			this->succ2.hostnametable_succ1[i]=message.hostname_value3;
			this->succ2.fingertable_succ2[i]=message.value4;
			this->succ2.hostnametable_succ2[i]=message.hostname_value4;
		}
	}
}

void node::closest_finger(unsigned int id){
	// check my fingertable and figure out which node to send to
}

// called periodically
void node::fix_fingers(){	// periodically refresh fingers
	// only fix fingers after succ list!
	unsigned int me=this->id;

	// it may be a bad idea to use this succ list for computing fingers directly?	

	// what we should do is only maintain fingers such that fingerid > fingertable[2*m-1].id
	
//	n->fingertable[2*m]=n->fingertable[0];
//	n->fingertable_succ1[2*m]=n->fingertable[1];
//	n->fingertable_succ2[2*m]=n->fingertable[2];
//	int breakpoint=3*m-1;

//	for(int i=2*m+1;i<3*m;i++){
//		if(simCanon_NodeId_Closer(me,n->fingerid[i],n->fingertable[0])==n->fingerid[i]){
//			n->fingertable[i]=n->fingertable[0];
//			n->fingertable_succ1[i]=n->fingertable[1];
//			n->fingertable_succ2[i]=n->fingertable[2];
//			continue;
//		}
//		for(int j=0;j<2*m-3;j++){
//			if(simCanon_NodeId_Closer(n->fingertable[j],n->fingerid[i],n->fingertable[j+1])==n->fingerid[i]){
//				n->fingertable[i]=n->fingertable[j+1];
//				n->fingertable_succ1[i]=n->fingertable[j+2];
//				n->fingertable_succ2[i]=n->fingertable[j+3];
//				break;
//			}
//			if(j==2*m-2){
//				if(i<breakpoint){
//					breakpoint=i;
//				}
//			}
//		}
//	}
	struct msg message;
	message.from=me;
	message.original_from=me;
	message.hostname_original_from=this->hostname;
	//message.hostname_from=this->hostname;
//	message.to=n->fingertable[n->next];			// use the lookup function already coded
	message.to=me;

	this->next=(this->next+1)%(3*m);
//	if(n->next<breakpoint){
//		n->next=breakpoint;
//		message.to=n->fingertable[breakpoint-1];
//	}
	if(this->next==0){
		this->next=2*m;
	}
	message.value=this->fingerid[this->next];
	
	message.ttl=0;
	message.path.push(me);	// always set ttl before issuing a lookup and add initiator to the path! 
	//Event evt2(Event::lookup,Clock,message.to,message);
	//FutureEventList.push(evt2);
	serialize_send(lookup_msg,this->hostname,message);


// lets fix one each of  my succ1 and succ2's fingers

//	breakpoint=3*m-1;
//	for(int i=2*m;i<3*m;i++){
		//assert(n->succ1.fingerid[i]==(n->succ1.id+(int)pow(2,i-2*m))%MAXID);
//		for(int j=0;j<2*m-3;j++){
//			if(simCanon_NodeId_Closer(n->fingertable[j],n->succ1.fingerid[i],n->fingertable[j+1])==n->succ1.fingerid[i]){
//				n->succ1.fingertable[i]=n->fingertable[j+1];
//				n->succ1.fingertable_succ1[i]=n->fingertable[j+2];
//				n->succ1.fingertable_succ2[i]=n->fingertable[j+3];
//				break;
//			}
//			if(j==2*m-2){
//				if(i< breakpoint){
//					breakpoint=i;
//				}
//			}
//		}
//	}
		
//	assert(this->succ1.fingertable[2*m]==this->fingertable[1]);
//	assert(this->succ2.fingertable[2*m]==this->fingertable[2]);

	struct msg message2;
	message2.from=me;
	message2.original_from=me;
	message2.hostname_original_from=this->hostname;
	//message2.to=n->succ1.fingertable[n->succ1.next];
	this->succ1.next=(this->succ1.next+1)%(3*m);
//	if(n->succ1.next < breakpoint){
//		n->succ1.next=breakpoint;
//		//message2.to=n->succ1.fingertable[breakpoint-1];
//	}
	if(this->succ1.next==0){
		this->succ1.next=2*m;

	}
	message2.value=this->succ1.fingerid[this->succ1.next];
	message2.ttl=0;
	message2.path.push(me);
	message2.to=me;
	//Event evt3(Event::lookup, Clock, message2.to,message2);
	//FutureEventList.push(evt3);
	serialize_send(lookup_msg,this->hostname,message);

//	breakpoint=3*m-1;
//	for(int i=2*m;i<3*m;i++){
		//assert(n->succ2.fingerid[i]==(n->succ2.id+(int)pow(2,i-2*m))%MAXID);
//		for(int j=0;j<2*m-3;j++){
//			if(simCanon_NodeId_Closer(n->fingertable[j],n->succ2.fingerid[i],n->fingertable[j+1])==n->succ2.fingerid[i]){
//				n->succ2.fingertable[i]=n->fingertable[j+1];
//				n->succ2.fingertable_succ1[i]=n->fingertable[j+2];
//				n->succ2.fingertable_succ2[i]=n->fingertable[j+3];
//				break;
//			}
//			if(j==2*m-2){
//				if(i<breakpoint){
//					breakpoint=i;
//				}
//			}
//		}
//	}
	struct msg message3;
	message3.from=me;
	message3.original_from=me;
	message3.hostname_original_from=this->hostname;
	//message3.to=n->succ2.fingertable[n->succ2.next];
	this->succ2.next=(this->succ2.next+1)%(3*m);
//	if(n->succ2.next < breakpoint){
//		n->succ2.next=breakpoint;
		//message3.to=n->succ2.fingertable[breakpoint-1];
//	}
	if(this->succ2.next==0){
		this->succ2.next=2*m;
	}
	message3.value=this->succ2.fingerid[this->succ2.next];
	message3.ttl=0;
	message3.path.push(me);
	message3.to=me;
	//Event evt4(Event::lookup, Clock, message3.to,message3);
	//FutureEventList.push(evt4);
	serialize_send(lookup_msg,this->hostname,message);

	// lets schedule fix_fingers again
	delaycb(fix_fingers_timer,0,wrap(this,&node::fix_fingers));
}

void node:: ping_reply(struct msg recv_message){
	unsigned int me=this->id;
	struct msg message=recv_message;
	//assert(n->pred==message.from);
}
void node::ping_timeout(){
	unsigned int me=this->id;
	this->pred=me;	// my predecessor is dead
	this->hostname_pred=this->hostname;
}

void node::ping(struct msg recv_message){
	unsigned int me=this->id;
	struct msg message=recv_message;
	message.to=message.from;
	message.from=me;
	//cout << "scheduling a ping reply ";
	//cout << "Priority queue size is " << FutureEventList.size() << " " ;
	//Event evt2(Event::ping_reply,Clock+latency[map[me]][map[message.to]],message.to,message);
	//FutureEventList.push(evt2);
	serialize_send(ping_reply_msg,message.hostname_from,message);
	//cout << "Priority queue size is " << FutureEventList.size() << " " ;
}

// called periodically
void node::check_predecessor(){	// checks if the predecessor has failed
	// send ping message to predecessor
	//warn << "My predecessor is " << this->hostname_pred << "\n";
	unsigned int me=this->id;
	struct msg message;
	message.from=me;
	message.to=this->pred;
	//assert(message.to!=me);
	//cout << "scheduling one ping event " ;
	if(this->pred!=me){
		//Event evt2(Event::ping,Clock+latency[map[me]][map[message.to]],message.to,message);
		//FutureEventList.push(evt2);
		serialize_send(ping_msg,this->hostname_pred,message);
	}
	//cout << "Priority queue size is " << FutureEventList.size();

	delaycb(check_predecessor_timer,0,wrap(this,&node::check_predecessor));	
	
	// set timeout event
	// if timeout event goes off, predecessor=nil
	// if receive ping reply, nullify timeout event
}

void node::notify(struct msg recv_message){	// i guess this is the action taken when the predecessor has failed
	// if predecessor is nil, or n' lies between predecessor,n
	// predecessor=n'
	
	unsigned int me=this->id;
//	assert(me==evt.get_id());
	struct msg message=recv_message;
	if(this->pred==this->id){	// this means pred=nil
		this->pred=message.from;
		this->hostname_pred=message.hostname_from;

		// check if i am the only node in the system 
		// in this case, the pred node is also my successor!
	       if(this->fingertable[0]==this->id){ // my succ is myself! 
	       		this->fingertable[0]=this->pred;
	 		this->hostnametable[0]=this->hostname_pred;
		}		
	}
	else if(simCanon_NodeId_Closer(message.from,this->pred,me)==message.from){
		this->pred=message.from;
		this->hostname_pred=message.hostname_from;
	}
	/* else if message.from lies between pred and me
		n->pred=message.from;
	}*/	
}

// called periodically
void node::stabilize(){	// key function to handle churn
	unsigned int me=this->id;
	/*for(int i=0;i<2*m;i++){
		warn << this->hostnametable[i] <<  " ";
	}
	warn << "\n\n\n";*/
	struct msg message;
	message.from=me;
	message.to=this->fingertable[0];
	warn << "My successor is " << this->hostnametable[0];
	//Event evt2(Event::get_pred,Clock+latency[map[me]][map[message.to]],message.to,message);
	//FutureEventList.push(evt2);
	serialize_send(get_pred_msg,this->hostnametable[0],message);

	delaycb(stabilize_timer,0,wrap(this,&node::stabilize)); // schedules functions after some time
}
// ************
void node::get_pred(struct msg recv_message){
	unsigned int me=this->id;
	//assert(me==evt.get_id());
	struct msg message=recv_message;
	message.to=message.from;
	message.from=me;
	message.value=this->pred;
	message.hostname_value=this->hostname_pred;
	for(int i=0;i<2*m;i++){
		message.fingertable[i]=this->fingertable[i];	// here's my succ list
		message.hostnametable[i]=this->hostnametable[i];
		if(message.hostnametable[i]==""){
			panic << me << " get_pred " << this->hostname << "\n";				assert(0);
		}

	}
	//Event evt2(Event::stabilize_reply,Clock+latency[map[me]][map[message.to]],message.to,message);
	//FutureEventList.push(evt2);	
	serialize_send(stabilize_reply_msg,message.hostname_from,message);
}

void node::stabilize_reply(struct msg recv_message){
	// i am just copying stuff from next guy? 
	// should i combine info from multiple sources?

	// if succ1 or succ2 changes, we should lookup all their fingers at once now, to maintain good reliability.

	unsigned int me=this->id;
	struct msg message=recv_message;
	for(int i=0;i<2*m;i++){
		if(message.hostnametable[i]==""){
			if(recv_message.hostnametable[i]!=""){
				panic << "My mistake";
			}	
		}
	}
	unsigned int x=message.value;
	/*if x lies between n,n's succ
		n->fingertable[0]=x;*/
	//assert(x==me);	// take this u=out for churn
	if(x!=me && simCanon_NodeId_Closer(me,x,this->fingertable[0])==x){
		this->fingertable[0]=x;		// i have a new succ
		this->hostnametable[0]=message.hostname_value;
		this->fingertable[1]=message.from;
		this->hostnametable[1]=message.hostname_from;
		//warn << "New successor : updating succ list\n";
		for(int i=2;i<2*m;i++){
			this->fingertable[i]=message.fingertable[i-2];
			this->hostnametable[i]=message.hostnametable[i-2];
			if(this->hostnametable[i]=="818287"){
				panic << message.from << " " << message.hostname_from << "\n";		}
		}
		/*for(int i=0;i<2*m;i++){
			warn << this->hostnametable[i] << " ";
		}
		warn <<"\n\n\n";*/
	}
	else{
		//warn << "Updating succ list\n";
		for(int i=1;i<2*m;i++){
			this->fingertable[i]=message.fingertable[i-1];
			this->hostnametable[i]=message.hostnametable[i-1];
			if(this->hostnametable[i]=="818287"){
				panic << message.from << " " << message.hostname_from << "\n";		}

		}
		/*for(int i=0;i<2*m;i++){
			warn << this->hostnametable[i] << " ";
		}
		warn <<"\n\n\n";*/

	}
	message.from=me;
	message.to=this->fingertable[0];
	//Event evt2(Event::notify,Clock+latency[map[me]][map[message.to]],message.to,message);
	//FutureEventList.push(evt2);
	serialize_send(notify_msg,this->hostnametable[0],message);


	// now lets update the shadow nodes if needed
	if(this->fingertable[0]==this->succ1.id && this->fingertable[1]==this->succ2.id){
		// nothing to do...the fingers of n->succ1 and n->succ remain the same
		
	}
	else if(this->fingertable[0]==this->succ2.id){		// succ1 failed
		// copy 2's data to 1...succ1 has failed
		this->succ1.id=this->succ2.id;
		this->succ2.id=this->fingertable[1];
		for(int i=2*m;i<3*m;i++){
			this->succ1.fingerid[i]=this->succ2.fingerid[i];
			this->succ1.fingertable[i]=this->succ2.fingertable[i];
			this->succ1.hostnametable[i]=this->succ2.hostnametable[i];
			// why am i not copying succ1 and succ2 of these fingers? 
			this->succ1.fingertable_succ1[i]=this->succ2.fingertable_succ1[i];
			this->succ1.hostnametable_succ1[i]=this->succ2.hostnametable_succ1[i];
			this->succ1.fingertable_succ2[i]=this->succ2.fingertable_succ2[i];
			this->succ1.hostnametable_succ2[i]=this->succ2.hostnametable_succ2[i];

			this->succ2.fingerid[i]=(this->succ2.id+(unsigned int)pow(2,i-2*m))%MAXID;
			// i need to build his tables
		}
		this->succ2.next=2*m;

		// lets fix succ2's finger
		struct msg message3;
		message3.from=me;
		message3.original_from=me;
		message3.hostname_original_from=this->hostname;
		message3.ttl=0;
		message3.path.push(me);
		message3.to=me;
		for(int i=2*m;i<3*m;i++){
			message3.value=this->succ2.fingerid[i];
			//Event evt4(Event::lookup, Clock, message3.to,message3);
			//FutureEventList.push(evt4);
			serialize_send(lookup_msg,this->hostname,message3);
		}		
	}
	else if(this->fingertable[1]==this->succ1.id){	// new succ added, succ 1 alive
		// new node added..copy 1 to w
		this->succ2.id=this->succ1.id;
		this->succ1.id=this->fingertable[0];
		for(int i=2*m;i<3*m;i++){
			this->succ2.fingerid[i]=this->succ1.fingerid[i];
			this->succ2.fingertable[i]=this->succ1.fingertable[i];
			this->succ2.hostnametable[i]=this->succ1.hostnametable[i];
			
			this->succ2.fingertable_succ1[i]=this->succ1.fingertable_succ1[i];
			this->succ2.hostnametable_succ1[i]=this->succ1.hostnametable_succ1[i];
			this->succ2.fingertable_succ2[i]=this->succ1.fingertable_succ2[i];
			this->succ2.hostnametable_succ2[i]=this->succ1.hostnametable_succ2[i];

			this->succ1.fingerid[i]=(this->succ1.id+(unsigned int)pow(2,i-2*m))%MAXID;
			// i need to build his tables
		}
		this->succ1.next=2*m;
		// lets fix succ1's finger
		struct msg message3;
		message3.from=me;
		message3.original_from=me;
		message3.hostname_original_from=this->hostname;
		message3.ttl=0;
		message3.path.push(me);
		message3.to=me;
		for(int i=2*m;i<3*m;i++){
			message3.value=this->succ1.fingerid[i];
			//Event evt4(Event::lookup, Clock, message3.to,message3);
			//FutureEventList.push(evt4);
			serialize_send(lookup_msg,this->hostname,message3);
		}

	}
	else if(this->fingertable[0]==this->succ1.id){	// succ2 failed/changed
		this->succ2.id=this->fingertable[1];
		for(int i=2*m;i<3*m;i++){
			this->succ2.fingerid[i]=(this->succ2.id+(unsigned int)pow(2,i-2*m))%MAXID;
		}
		this->succ2.next=2*m;

		// lets fix succ2's finger
		struct msg message3;
		message3.from=me;
		message3.original_from=me;
		message3.hostname_original_from=this->hostname;
		message3.ttl=0;
		message3.path.push(me);
		message3.to=me;
		for(int i=2*m;i<3*m;i++){
			message3.value=this->succ2.fingerid[i];
			//Event evt4(Event::lookup, Clock, message3.to,message3);
			//FutureEventList.push(evt4);
			serialize_send(lookup_msg,this->hostname,message3);
		}
	}
	else{
		// 2 new nodes or both succ1/succ2 failed
		this->succ1.id=this->fingertable[0];
		this->succ2.id=this->fingertable[1];
		for(int i=2*m;i<3*m;i++){
			this->succ1.fingerid[i]=(this->succ1.id+(unsigned int)pow(2,i-2*m))%MAXID;
			
			this->succ2.fingerid[i]=(this->succ2.id+(unsigned int)pow(2,i-2*m))%MAXID;
			// i need to build both the tables
		}
		this->succ1.next=2*m;
		this->succ2.next=2*m;
		// lets fix succ1 and succ2's finger
		struct msg message3;
		message3.from=me;
		message3.original_from=me;
		message3.hostname_original_from=this->hostname;
		message3.ttl=0;
		message3.path.push(me);
		message3.to=me;
		for(int i=2*m;i<3*m;i++){
			message3.value=this->succ1.fingerid[i];
			//Event evt4(Event::lookup, Clock, message3.to,message3);
			//FutureEventList.push(evt4);
			serialize_send(lookup_msg,this->hostname,message3);
		}
		for(int i=2*m;i<3*m;i++){
			message3.value=this->succ2.fingerid[i];
			//Event evt4(Event::lookup, Clock, message3.to,message3);
			//FutureEventList.push(evt4);
			serialize_send(lookup_msg,this->hostname,message3);
		}
	}
	
	// lets keep the old nodes fingers...they should be refreshed soon by fix fingers
	// actually for chord, the fingers would be quite similar
	
}

void node::stabilize_timeout(){
	//return;
	unsigned int me=this->id;
	struct msg message; // this means that my immediate succ is dead
	panic << "Stabilize_timeout\n";	
	// restructure the succ list and reschedule get_pred
	//
	for(int i=0;i<2*m-1;i++){
		this->fingertable[i]=this->fingertable[i+1];
		this->hostnametable[i]=this->hostnametable[i+1];
	}
	//assert(n->fingertable[0]==succ_alive(me+1));
	message.from=me;
	message.to=this->fingertable[0];
	//Event evt2(Event::get_pred,Clock+latency[map[me]][map[message.to]],message.to,message);
	//FutureEventList.push(evt2);
	serialize_send(get_pred_msg,this->hostnametable[0],message);
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

unsigned int simCanon_NodeId_Closer(unsigned int idsrc1, unsigned int idsrc2, unsigned int iddest) {

  if (simCanon_NodeId_IncreasingDistance(idsrc1,iddest)<simCanon_NodeId_IncreasingDistance(idsrc2,iddest))
    return idsrc1;
  else
    return idsrc2;
}

#ifdef simulation
void node_dead(Event evt, struct node *n){
	//cout << Clock << "Dead" << endl;
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
#endif

#ifdef simulation
void node_alive(Event evt, struct node *n){
	//cout << Clock << "Alive" << endl;
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

	Event evt2(Event::stabilize,Clock+stabilize_timer,message.to,message);
	FutureEventList.push(evt2);
	
	Event evt3(Event::fix_fingers,Clock+fix_fingers_timer,message.to,message);
	FutureEventList.push(evt3);
	
	Event evt4(Event::node_dead,Clock+guard_timer+pareto_stream(mean_alive_rate),message.to,message);
	FutureEventList.push(evt4);
	
	Event evt5(Event::initiate_path,Clock+path_timer+sign_timer*2,message.to,message); // signed certificates should have been received
	FutureEventList.push(evt5);

}
#endif

void node::sign_state(){

	unsigned int me=this->id;
	struct msg message;
	message.from=me;
	message.to=this->fingertable[0];
	for(int i=2*m;i<3*m;i++){
		message.fingertable[i]=this->succ1.fingertable[i];
		message.fingertable_succ1[i]=this->succ1.fingertable_succ1[i];
		message.fingertable_succ2[i]=this->succ1.fingertable_succ2[i];
	}
	//Event evt1(Event::recv_sign, Clock+latency[map[me]][map[message.to]], message.to,message);
	//FutureEventList.push(evt1);
	serialize_send(recv_sign_msg,this->hostnametable[0],message);

	message.to=this->fingertable[1];
	for(int i=2*m;i<3*m;i++){
		message.fingertable[i]=this->succ2.fingertable[i];
		message.fingertable_succ1[i]=this->succ2.fingertable_succ1[i];
		message.fingertable_succ2[i]=this->succ2.fingertable_succ2[i];
	}

	//Event evt2(Event::recv_sign, Clock+latency[map[me]][map[message.to]], message.to,message);
	//FutureEventList.push(evt2);
	serialize_send(recv_sign_msg,this->hostnametable[1],message);

	//message.to=n->id;
	//Event evt3(Event::sign_state,Clock+sign_timer,message.to,message);
	//FutureEventList.push(evt3);
	delaycb(sign_timer,0,wrap(this,&node::sign_state));
}

void node::recv_sign(struct msg recv_message){

	struct msg message=recv_message;
	if(this->pred==message.from){
		this->pred=message.from;
		for(int i=2*m;i<3*m;i++){
			this->pred_fingertable[i]=message.fingertable[i];
			this->pred_fingertable_succ1[i]=message.fingertable_succ1[i];
			this->pred_fingertable_succ2[i]=message.fingertable_succ2[i];
		}
	}
	else{ //if(succ_alive(succ_alive(message.from+1)+1)==this->id){
		this->pred1=message.from;	// hope this doesnt lead to oscillations! 
		for(int i=2*m;i<3*m;i++){
			this->pred1_fingertable[i]=message.fingertable[i];
			this->pred1_fingertable_succ1[i]=message.fingertable_succ1[i];
			this->pred1_fingertable_succ2[i]=message.fingertable_succ2[i];
		}
	}
}

void node::initiate_path(){
	// without churn things seem to be working just fine
	
	path_count++;	

	unsigned int me=this->id;
	struct msg message;
	message.from=me;;
	message.to=me;	
	//Event evt5(Event::initiate_path,Clock+path_timer,message.to,message); // signed certificates should have been received
	//FutureEventList.push(evt5);
	//delaycb(path_timer,0,wrap(initiate_path));
// This doesnot make much sense - intiate path should not be a periodic event - it should be on demand! 

	int random=rand()%m;
	unsigned int next_hop=this->fingertable[2*m+random];
	unsigned int next_hop_succ1=this->fingertable_succ1[2*m+random];	// damn the shadows are actually the predecessors!==> i need to know the node and its predecessors
	unsigned int next_hop_succ2=this->fingertable_succ2[2*m+random];

}

void node::extend_path(){

}

#ifdef simulation
double exponential_stream(double mean_rate){
	
	double uniform, exponential;
	uniform =  (double) (1.0 * (rand() / (RAND_MAX + 1.0)));	
	exponential= ((-1/mean_rate)*log(1-uniform));
	return exponential;
}

double pareto_stream(double mean_rate){	// unit of everything is seconds...so we get seconds out of this function
	double mean=1/mean_rate;
	double uniform, pareto;
	uniform =  (double) (1.0 * (rand() / (RAND_MAX + 1.0)));
	double a=2;
	double b=(a-1)*mean;
	pareto = b*(1/pow(uniform,1/a)-1);
	return pareto;
}
#endif


tamed static
void send(strbuf hostname, strbuf req){
	//warn << "Entering send\n";
	// figure out the ip address and port(hardcode to default?) of the destination
	tvars{
		int fd;
		int n;		
		//strbuf hostname;
		//short port;
		str str_req;
		string string_req;
		stringstream ss_req;
		int type;
	}
	twait{
		tcpconnect(hostname,port,mkevent(fd));
	}
	if(fd < 0){
		//warn("Connection failed\n");
		str_req=req;
		string_req= (string)str_req;
		ss_req << string_req; //((char *)req);
		ss_req >> type;
		switch(type){
			case get_pred_msg: allnodes[0].stabilize_timeout();
				       break;
			case ping_msg: allnodes[0].ping_timeout();
				   break;
			default:
				break;
		}				
		return;
	}
	twait{
		fdcb(fd,selwrite,mkevent());
	}
	n=req.tosuio()->output(fd);
	if(n < 0){
		//warn("write error\n");
	
	}
	if(req.tosuio()->resid()){
		return;
	}
	else{
		fdcb(fd,selwrite,0);
		// note that you can utilize the open socket to get a response
		// but for now, let me close the socket (otherwise who will close them?)
		close(fd);
	}	

}

void serialize_send(int type, str dst_hostname,struct msg message){
	//warn << "Entering serialize_send\n";
	strbuf req;
	//unsigned int message_id=(unsigned int)rand();
	//req << message_id;
	req << type << " " ; // first part has to be the message type
	// then we need to put in a from field (can simply be an id)
	req << message.from << " ";
	req << allnodes[0].hostname << " "; // non-spoofable
	// to field needs to be passed on to the send function as well
	req << message.to << " ";
	switch(type){
		case lookup_msg: // add lookup id, ttl, failed nodes stack
				req << message.original_from << " ";
				req << message.hostname_original_from << " ";
				req << message.value << " ";
				req << message.ttl << " ";
				req << message.path.size() << " ";
				while(message.path.size()!=0){
					req << message.path.top() << " ";
					message.path.pop();
				}
				// add stack (path)
				break;
		case lookup_reply_msg: // add the lookup id, response
				//warn << "Case : lookup_reply_msg\n";
				req << message.value << " ";
				//req << message.hostname_value << " ";
				req << message.value2 <<  " ";
				req << message.hostname_value2 << " " ;
				req << message.value3 << " ";
				req << message.hostname_value3 << " ";
				req << message.value4 << " ";
				req << message.hostname_value4 << " ";
				break;
		case ping_msg:  // nothing else to add (confirmed)
				break;
		case ping_reply_msg: // nothing else to add (confirmed)
				break;
		case get_pred_msg: // nothing else to add (confirmed)
			
				break;
		case stabilize_reply_msg: // add value, fingertable[i]
				req << message.value << " ";
				req << message.hostname_value << " ";
				for(int i=0;i<2*m;i++){
					req << message.fingertable[i] << " ";
					req << message.hostnametable[i] << " ";						if(message.hostnametable[i]==""){
						warn <<"Sending error\n";
	panic << message.from << " " << message.hostname_from << " " << /*message_id <<*/ "\n";
					}

				}
				//warn << "Sending : " << req << "\n\n";
				break;
		case notify_msg: // nothing else to add (confirmed)
				break;
		case recv_sign_msg: // add the signature, state
				for(int i=2*m;i<3*m;i++){
				req << message.fingertable[i] <<" ";
				req << message.fingertable_succ1[i] << " ";
				req << message.fingertable_succ2[i] <<  " ";
				}
				break;
		case debug_state_msg: 
				break;
		case debug_state_reply_msg: 
				for(int i=0;i<2*m;i++){
					req << message.fingertable[i] << " ";
				}
				for(int i=2*m;i<3*m;i++){
					req << message.fingertable[i] << " ";
					req << message.fingertable_succ1[i] << " ";
					req << message.fingertable_succ2[i] << " " ;
				}
		default:
				break;
	}
	if(dst_hostname==allnodes[0].hostname){	// message to myself! 
		// hmm - only message that makes sense is lookup
		if(type==lookup_msg){
			// directly make a function call! 
			deserialize_recv(req);
		}
		// doesnt't make sense to send any other message to myself
	}
	else{
		send(dst_hostname,req);
	}
}

void deserialize_recv(strbuf req){
	//warn << "Deserializing message\n";
	str str_req=req;
	struct msg message;
	int type;
	//unsigned int message_id;
	string string_req= (string)str_req;
	stringstream ss_req(string_req); //((char *)req);
	//ss_req >> message_id;
	ss_req >> type; 
	ss_req >> message.from;
	string hostname_from;
	//ss_req >> message.hostname_from;
	ss_req >> hostname_from;
	message.hostname_from=(char *)hostname_from.c_str();
	ss_req >> message.to;
	string hostname_original_from;
	string hostname_value;
	string hostname_value2;
	string hostname_value3;
	string hostname_value4;
	string hostnametable;
	switch(type){
		case lookup_msg: // add lookup id, ttl, failed nodes stack
				//warn << "Entering case lookup_msg \n";
				ss_req >> message.original_from;
				ss_req >> hostname_original_from;
				message.hostname_original_from=(char *)hostname_original_from.c_str();	
				ss_req >> message.value;
				ss_req >> message.ttl;
				int path_size;
				unsigned int element;
				ss_req >> path_size;
				while(message.path.size()!=path_size){
					ss_req >> element;
					message.path.push(element);
				}
				// add stack (path)
				//warn << "Calling the lookup function\n";
				allnodes[0].lookup(message);
				break;
		case lookup_reply_msg: // add the lookup id, response
				ss_req >> message.value; 
				//ss_req >> hostname_value;
				//message.hostname_value=(char *)hostname_value.c_str();
				ss_req >> message.value2;
				ss_req >> hostname_value2;
				message.hostname_value2=(char *)hostname_value2.c_str();
				ss_req >> message.value3;
				ss_req >> hostname_value3;
				message.hostname_value3=(char *)hostname_value3.c_str();

				ss_req >> message.value4;
				ss_req >> hostname_value4;
				message.hostname_value4=(char *)hostname_value4.c_str();

				allnodes[0].lookup_reply(message);
				// ADD HOSTNAME VALUeS
				break;
		case ping_msg:  // nothing else to add (confirmed)
				allnodes[0].ping(message);
				break;
		case ping_reply_msg: // nothing else to add (confirmed)
				allnodes[0].ping_reply(message);
				break;
		case get_pred_msg: // nothing else to add (confirmed)
				allnodes[0].get_pred(message);
				break;
		case stabilize_reply_msg: // add value, fingertable[i]
				ss_req >> message.value;
				ss_req >> hostname_value;
				message.hostname_value=(char *)hostname_value.c_str();
				for(int i=0;i<2*m;i++){
					ss_req >> message.fingertable[i];
					ss_req >> hostnametable;
					message.hostnametable[i]=(char *)hostnametable.c_str();
					if(message.hostnametable[i]=="818287" || message.hostnametable[i]==""){
						warn << "Receiving " << req << "\n\n";
	panic << message.from << " " << message.hostname_from << " " << /*message_id <<*/ "\n";
					}

				}
				allnodes[0].stabilize_reply(message);
				break;
		case notify_msg: // nothing else to add (confirmed)
				allnodes[0].notify(message);
				break;
		case recv_sign_msg: // add the signature, state
				for(int i=2*m;i<3*m;i++){
				ss_req >> message.fingertable[i];
				ss_req >> message.fingertable_succ1[i];
				ss_req >> message.fingertable_succ2[i];
				}
				allnodes[0].recv_sign(message);
				break;
		case debug_state_msg:
				allnodes[0].debug_state(message);
				break;
		case debug_state_reply_msg:
				for(int i=0;i<2*m;i++){
					ss_req >> message.fingertable[i];
				}
				for(int i=2*m;i<3*m;i++){
					ss_req >> message.fingertable[i];
					ss_req >> message.fingertable_succ1[i];
					ss_req >> message.fingertable_succ2[i];
				}
				allnodes[0].debug_state_reply(message);
				break;
		default:
				//warn << "Message of unknown type received\n";
				break;
	}

}

void recv_msg(int sock_id, strbuf buf){
	//warn << "Read event triggered\n";
	int n=buf.tosuio()->input(sock_id);
	if(n <0){
		//warn << "read \n";
	}
	else if(n==0){	// socket closed by sender - should disable callback
		//warn << "Perhaps i should close the socket now\n";
		//panic << buf;
		fdcb(sock_id,selread,0);
		close(sock_id);
		deserialize_recv(buf);
		// we should also call deserialize at this point now! 
		return;
	}
	else{	//warn << "Read: " << buf << "\n";
		// possibly more stuff to be read, donot disable callback! 
		//warn << "Received message: " << buf << "\n";
		//	deserialize_recv(buf);
	}

	// now we can decode the message and call the appropriate function
	// this should not be too hard
}
