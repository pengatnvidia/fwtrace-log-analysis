usage:  
(1) for SPDM  

    python3 fw.trace.analysis.py  <fwtrace.log>  >  <fwtrace.analysis.output>  
    python3 get.certificate.py    <fwtrace.analysis.output>  #this command will get the SPDM output 


(1.1) how to read the SPDM output  

find the below 3 lines:    
   "calculated certchain hash" means the hash value calculated by the full cert without root.hash and without cert header; same as Digest response.     
   "calculated certchain hash(including header+roothash)" means the hash value calculated by full cert with root.hash and with cert header; same as Challenge response.  
   "CHALLENGE_certchain_hash" comes from the response of the SPDM challenge command;  
below is example,   

slot mask = 1 calculated certchain hash = 465cb3fe84c79a454450f03046553ef62329cdebcbfb814b109bedd40f872d817269c18682be8f51ebec0b3d8b40f613  
calculated certchain hash(including header+roothash) = f23629e6dbbfe4d4f6d7f8b0f7401350b5618d7888a9b736b2659af911442a950247349cf90b7ae03c05225a9c3e7524  
slot_mask = 1  CHALLENGE_certchain_hash = f2deb6da41fbc02c90581232716b943d154c53d6f71761893fe8f56433e8c87b2ca020a5baf47b3778fea6e657cf384f  

