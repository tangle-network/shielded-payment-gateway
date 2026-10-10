// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 16428432848801857252194528405604668803277877773566238944394625302971855135431;
    uint256 constant alphay  = 16846502678714586896801519656441059708016666274385668027902869494772365009666;
    uint256 constant betax1  = 3182164110458002340215786955198810119980427837186618912744689678939861918171;
    uint256 constant betax2  = 16348171800823588416173124589066524623406261996681292662100840445103873053252;
    uint256 constant betay1  = 4920802715848186258981584729175884379674325733638798907835771393452862684714;
    uint256 constant betay2  = 19687132236965066906216944365591810874384658708175106803089633851114028275753;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 7137980709977238240264574414725874062999155166405375186703201804624123858245;
    uint256 constant deltax2 = 6590895319189850561928952163382661319680046827073918203766075924264600107634;
    uint256 constant deltay1 = 1058114257745122862270633577439561185489744394125871413523773240861523127113;
    uint256 constant deltay2 = 20821791081515550713244426295707210483403189065493111948661517270606531399210;

    
    uint256 constant IC0x = 20550391235535929755245083244367382532500117796568629294086031166942795864708;
    uint256 constant IC0y = 10455742266573700745028015743770570623227971979632367070019847863982763426495;
    
    uint256 constant IC1x = 9964036687357637966120099624801829426712315742983846628474025703090465873200;
    uint256 constant IC1y = 12204660578703139343017160048356346332887822774320457410882115578253574548636;
    
    uint256 constant IC2x = 17033837976658714404365280459193378542726756576726687858032634027855180320842;
    uint256 constant IC2y = 13757003962070699085320810648588728580949948450838434358887728903349287142553;
    
    uint256 constant IC3x = 918245508774582837736278090660384873658701840546457613034676095467964228513;
    uint256 constant IC3y = 15163779961571944769031660329633329011755420202016669319290102017050234105219;
    
    uint256 constant IC4x = 19596046005569313837650158377002508969018172555937539250653467790750415456425;
    uint256 constant IC4y = 6664763697148406209248491636665577839887099934638083480567714024886860619677;
    
    uint256 constant IC5x = 8891398582279484333451552010994911844308505997242826101639296033030818931364;
    uint256 constant IC5y = 16646037272914299650525725777362412143686452047307117931954329066224237208489;
    
    uint256 constant IC6x = 6831250694826372171082490226691776989697805965640722012068455117587967821120;
    uint256 constant IC6y = 5327094730264988385639579601055974453851867552143216377327222255707090527645;
    
    uint256 constant IC7x = 9017375841353145309627809672929858609965815904605753949881685437290475983083;
    uint256 constant IC7y = 17864241836715880883007324308047753343961461040508368119082406531293642610158;
    
    uint256 constant IC8x = 310561526473827360259374206113990993354123134509847223660074952592358555867;
    uint256 constant IC8y = 7445072631492273255945367168977699560619598530989299443172829615032830427170;
    
    uint256 constant IC9x = 6853120175894309869865149391023723661334323123602563598947131397123804297203;
    uint256 constant IC9y = 11712938131905080608315280054466801966349326142809971489211275983164168749900;
    
    uint256 constant IC10x = 880219305043094812988445413049398565332002229634818280940271488669103954357;
    uint256 constant IC10y = 20954230785575027581298907857624085124645810372511962497220323864479528159924;
    
    uint256 constant IC11x = 16937786239649993566403105888184771089897090093403271977500885056361165340402;
    uint256 constant IC11y = 21071735747180567955664957338484956317938303503528402486126315402742854425008;
    
    uint256 constant IC12x = 8112062188612905066186538949315484062862841457062296812946568454769262553085;
    uint256 constant IC12y = 3529294833528033734142337794288166234204006107943109847819799697786903442493;
    
    uint256 constant IC13x = 7197823705027649847405745761614114455561174844645210049656281365164181701396;
    uint256 constant IC13y = 19991485535748400205386535361772413245405640179822299447326213319107853840971;
    
    uint256 constant IC14x = 17374713518710636591519521158903857661761197470471905513464203235875933975454;
    uint256 constant IC14y = 18487996406342415412006226574495944711899336901037905066784836280950890581176;
    
    uint256 constant IC15x = 18786727407735784897283595083474792808964855671578868430288903627773587438925;
    uint256 constant IC15y = 17009491165295878761744596179259570514800739673647876994147118554570702656599;
    
    uint256 constant IC16x = 21464426164620064126449372971643985704586579142813600809385905720097939798546;
    uint256 constant IC16y = 20631516357916658323804025626297221992599272178596434979088544929493614672826;
    
    uint256 constant IC17x = 21213941415331320981776798305770700632893702352606744071676548171255186838646;
    uint256 constant IC17y = 3621663862922417628450738145682798007230046183047423265494435884783423514496;
    
    uint256 constant IC18x = 19286640976774253300365781661284914821277136799591635527015461248407848756955;
    uint256 constant IC18y = 3999035580647437732177458355724673579491033813593544452909716925714503362811;
    
    uint256 constant IC19x = 4127934540249783016107173893045807204795095037172523338351507463379304783776;
    uint256 constant IC19y = 1747099737753985845215463901320437498667379964954036194645881118072072555103;
    
    uint256 constant IC20x = 3096349734437743468756009487688094233103445610761055432722401193930451235404;
    uint256 constant IC20y = 21492013473224872262269271227151800726054710351778267380359950538582042654201;
    
    uint256 constant IC21x = 10761951166289562335140129348954537109349758586871910511866629253843468976051;
    uint256 constant IC21y = 2813156688903996972058493624509138283996277976342350591487781652725893716149;
    
    uint256 constant IC22x = 11315454183792580187416361638220988972068953222077899739154210973738106738813;
    uint256 constant IC22y = 1624538669465827040247181828861716900232600945727886491775603735207835041108;
    
    uint256 constant IC23x = 15150176908536433668201854125007432887875022663592616183810844878010477922516;
    uint256 constant IC23y = 1040095222245393922858431564350331453059046199817317479414461050096175382871;
    
    uint256 constant IC24x = 11625546537302017754436120664318510398196093117152356443639732476942089962152;
    uint256 constant IC24y = 3099948774043155736634350452792140943753852720073025978240557386656943310865;
    
    uint256 constant IC25x = 6221979764452107473740370692320721173537616169316772141442793077904863692765;
    uint256 constant IC25y = 2544689213248160003809015545222758667633152126918883480215550755238640676960;
    
    uint256 constant IC26x = 13956898543708971818855172194320817475573423820360087204869096765411894647535;
    uint256 constant IC26y = 18690824311997353892584734713240414782918592408332194335686260559126700185556;
    
    uint256 constant IC27x = 14319233617655973901128282556270917903610863798189396343151574572389515822341;
    uint256 constant IC27y = 12805456941527605016954244496200163822635303568787249952602352274901500686728;
    
    uint256 constant IC28x = 563796410346575344410418056417425151288990380022332685699656759906815658367;
    uint256 constant IC28y = 8236376563442897862589057450821007867261800749758867604570074124607346363286;
    
    uint256 constant IC29x = 13861984645397952294030919256143766946160075281879236715748606436634763863554;
    uint256 constant IC29y = 12579497038482415950459756208166715741314135126129552623149842351957728369476;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[29] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
