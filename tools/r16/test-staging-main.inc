int main(){
 {RTL8125 d;IOService o;install(d,o);Mbuf m[4],other;other.token=8;
 UInt64 physical[4]{};
 for(unsigned i=0;i<4;i++){
  IOPhysicalSegment s[2]={{0x400000ff0,32},{0x500000004,42}};UInt32 n=2;
  if(!i)assert(d.r16TxMap(&other,s,n)&&n==2&&maps==0);
  m[i].req=i+1;assert(d.r16TxMap(&m[i],s,n));
  assert(n==1&&s[0].length==74&&s[0].location==0x1000000000ULL);
  physical[i]=d.r16Tx->request.physical[0].address;
  assert(physical[i]==d.r16Tx->stagingPA[i]&&!(physical[i]&4095));
  for(unsigned j=0;j<i;j++)assert(physical[j]!=physical[i]);
  assert(!memcmp(d.r16Tx->staging[i]->getBytesNoCopy(),m[i].data,74));
  assert(nativeAlive==4&&d.r16Tx->request.count==1);
  Mbuf busy;assert(!d.r16TxMap(&busy,s,n)&&busy.frees==1);
  unsigned slot=d.txNextDescIndex;
  int before=retires;d.r16TxComplete((slot+1)&1023);
  assert(d.r16Tx->state==r16tx::kSubmitted&&retires==before);
  d.txDescArray[slot]={s[0].location,0x8000004a,0};
  d.r16TxPosted(&m[i]);d.r16TxComplete(slot);
  assert(d.r16Tx->state==r16tx::kPending&&!m[i].frees&&retires==before);
  if(!i){retireMode=1;d.r16TxTimer(d.r16Tx->timer);
   assert(d.r16Tx->state==r16tx::kPending&&!m[i].frees&&nativeAlive==4);retireMode=0;}
  d.r16TxTimer(d.r16Tx->timer);
  auto&w=d.r16Tx->snapshot.witnesses[i];
  assert(d.r16Tx->state==0&&!m[i].frees&&nativeAlive==4);
  assert(w.request.handle&&w.tOwn&&w.request.tDone>w.tOwn&&w.request.tRetire>w.request.tDone);
  assert(w.descriptors[0].address==s[0].location&&w.lastSlot==slot&&!w.tFree);
  d.txNextDescIndex=(slot+1)&1023;d.txTailPtr0++;
 }
 assert(d.r16Tx->copiedBytes==296);
 auto c=control(r16tx::kDetach);completeFail=true;
 assert(d.r16TxConfigure(&c)==88&&nativeAlive==4&&o.refs==2);
 for(unsigned i=0;i<4;i++)assert(!m[i].frees&&!d.r16Tx->snapshot.witnesses[i].tFree);
 completeFail=false;finish(d,o);assert(nativeAlive==0);
 for(unsigned i=0;i<4;i++){auto&w=d.r16Tx->snapshot.witnesses[i];assert(m[i].frees==1&&w.tFree>m[i].freedAt&&w.tFree>w.request.tRetire);}
 assert(d.r16Tx->snapshot.witnesses[3].tFree>lastNativeRelease);
 Mbuf late;IOPhysicalSegment s{0x400000000,74};UInt32 n=1;assert(!d.r16TxMap(&late,&s,n)&&late.frees==1);
 }
 for(int mode=1;mode<=3;mode++){
  RTL8125 d;IOService o;install(d,o);mapMode=mode;Mbuf m;
  IOPhysicalSegment s{0x400000000,74};UInt32 n=1;assert(!d.r16TxMap(&m,&s,n));
  if(mode==1)assert(m.frees==1&&d.r16Tx->state==0);
  else {assert(!m.frees&&d.r16Tx->state==r16tx::kPending);
   d.r16TxTimer(d.r16Tx->timer);assert(!m.frees&&d.r16Tx->state==0&&nativeAlive==4);}
  finish(d,o);assert(m.frees==1&&nativeAlive==0);
 }
 mapMode=0;
 {RTL8125 d;IOService o;install(d,o);Mbuf m;UInt32 n=1;int before=maps;
  IOPhysicalSegment s{0x400000000,4097};m.len=4097;
  assert(!d.r16TxMap(&m,&s,n)&&m.frees==1&&maps==before);
  Mbuf copy;copyFail=true;s={0x400000000,74};assert(!d.r16TxMap(&copy,&s,n)&&copy.frees==1&&maps==before);copyFail=false;
  Mbuf v;d.useAppleVTD=true;assert(!d.r16TxMap(&v,&s,n)&&v.frees==1);d.useAppleVTD=false;
  Mbuf page;page.len=4096;s={0x400000000,4096};assert(d.r16TxMap(&page,&s,n)&&n==1);
  auto c=control(r16tx::kDisarm);assert(d.r16TxConfigure(&c)==kIOReturnBusy);
  d.r16TxPosted(&page);d.r16TxComplete(d.txNextDescIndex);d.r16TxTimer(d.r16Tx->timer);finish(d,o);
 }
 for(int failure=0;failure<2;failure++){
  RTL8125 d;IOService o;d.r16Tx=nullptr;prepareFail=failure==0;badAlignment=failure==1;
  auto c=control(r16tx::kInstall);c.bdf=0x2500;c.token=7;c.deadline=100000;c.callback=backend;c.context=&o;c.owner=&o;
  assert(d.r16TxConfigure(&c)==kIOReturnNoResources&&o.refs==1&&!d.r16Tx&&nativeAlive==0);
  prepareFail=false;badAlignment=false;
 }
 {RTL8125 d;IOService o;install(d,o);IOPhysicalSegment s{0x400000000,74};UInt32 n=1;Mbuf m;
  assert(d.r16TxMap(&m,&s,n));d.r16TxStop();
  assert(!m.frees&&o.refs==2&&nativeAlive==4&&d.r16Tx->state==r16tx::kSubmitted);
 }
 puts("PASS: actual page-aligned real TX staging, byte copy/count flatten, exact IOVA reuse+distinct PA, deferred Retire/quarantine, complete failure pin, dual-owner free timestamps, stop pin");
}
