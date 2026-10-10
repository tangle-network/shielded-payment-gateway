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
    uint256 constant deltax1 = 4789640742447246975354079559997200967310098665858139802224808889816998556300;
    uint256 constant deltax2 = 16224237516873286364614178339120627861702695169388732323702840143610369458263;
    uint256 constant deltay1 = 6026523423516661496755772648249194275689801407657039912200615161812884452335;
    uint256 constant deltay2 = 7316960900561607311129240006962360362183381716233118256745468913043423151175;

    
    uint256 constant IC0x = 13334755828754558873559730345987775832524142196865080708595904414201194810124;
    uint256 constant IC0y = 7137076354339989012243901442968989912145074926702181292642647100496838804396;
    
    uint256 constant IC1x = 8821873014860388664125457915802698658105894931097710743390885002875631792699;
    uint256 constant IC1y = 17000984415282982912274543543896106804757289490327040849172713932901362992961;
    
    uint256 constant IC2x = 4189041449130983411616726478170250405671756133331300514756240378505859005833;
    uint256 constant IC2y = 8484871335518449942043809701590066377818394896426189626990541954511636262274;
    
    uint256 constant IC3x = 5583365099835113030260415681996302772663569032656309379021180575263672550251;
    uint256 constant IC3y = 7857508412919851891108875148209338159597220831541527519822841697382275059965;
    
    uint256 constant IC4x = 5182855331345658843482067691524529380872291698056178646411365808699332519690;
    uint256 constant IC4y = 5925076074176614570565178606472069486735490220574010693099308469123526550540;
    
    uint256 constant IC5x = 3769895089649896608787196147299589826031428403885517037367016113011089868770;
    uint256 constant IC5y = 19236904022447833115409251306260813823628677768722684493510392056264535153794;
    
    uint256 constant IC6x = 14652263950191449304304671303249620414231640207915028194700898104734235334715;
    uint256 constant IC6y = 6572709663194636075000105158712664700974314559159575379926407418313043405241;
    
    uint256 constant IC7x = 9235861103449170094856203929655187371310678427783821316412730451884380696419;
    uint256 constant IC7y = 7437992022527294200964260988526681167282315696354167214497324671213694874929;
    
    uint256 constant IC8x = 12489417702823085695280420206925717440735727245417537053659840770847244093429;
    uint256 constant IC8y = 18232034512500768460136656120328033056760555087662525444395650054600359222190;
    
    uint256 constant IC9x = 100717600925481033255047053360108116223230091755192074895899066613804885286;
    uint256 constant IC9y = 8349926245832679945937284957367658695107681341173286172247594023706703832765;
    
    uint256 constant IC10x = 5473412113575440518646490404144524342760180028293820991305610904111617701355;
    uint256 constant IC10y = 21581606741291796774515573119477924975056644295797241432365068578413133370020;
    
    uint256 constant IC11x = 5273409736837185339028792261243586753110445848031271912113033286494724182457;
    uint256 constant IC11y = 2692115643616915916598363759241430790116055057736349841277279789407331852885;
    
    uint256 constant IC12x = 12396457010141057522545015590081500248574271657118839728359232684674061399089;
    uint256 constant IC12y = 14378009749662214635288548618305272928179834043667206707824295310460241569290;
    
    uint256 constant IC13x = 4459922414779090735769599992637735134391864230152417329568832899376864027694;
    uint256 constant IC13y = 18815228641160378965785301689836006696075847343214566201444454769907394860201;
    
    uint256 constant IC14x = 20648821988115325362690894218041936973768712514016829295671246468053316163680;
    uint256 constant IC14y = 15930308987288993319082974968923523917194795000859127287496049889647034432200;
    
    uint256 constant IC15x = 16257308448179658908932371617309975980414151524735756533460069344642442442679;
    uint256 constant IC15y = 15224190980095414519403612359695342483927913051512150108119204292724535039088;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[15] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
