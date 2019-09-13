#include <iostream>
#include <vector>
#define MAX_N 50000 + 1
using namespace std;

bool notprime[MAX_N];
vector<int> prime;

void isprime(){
	for(int i = 2; i < MAX_N; i++){
		if(!notprime[i]) prime.push_back(i);
		for(int j = 1; i * j < MAX_N; j++)
			notprime[i * j] = true;
	}
}

int main(){
	isprime();
	for(int i = 0; i < prime.size(); i++)
		cout << prime[i] << " ";
	cout << endl;
	return 0;
}