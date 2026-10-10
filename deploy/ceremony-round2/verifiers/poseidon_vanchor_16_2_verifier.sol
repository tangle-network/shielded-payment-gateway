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
    uint256 constant deltax1 = 13553251514123373830251656828256239558662780731423875462453635705211155475614;
    uint256 constant deltax2 = 21676262953268554013724098348410899673970023351478327461147531069874932712976;
    uint256 constant deltay1 = 7339618217125937448249389936748999466252114959575610843650510003049292363349;
    uint256 constant deltay2 = 14188857615674066734884557546855776512695560334068732907084316171729466556636;

    
    uint256 constant IC0x = 3757412427390121189079201569856011460686386659667710084278134714548218750042;
    uint256 constant IC0y = 6327023239329929332701613298411002661064478375706675134969601443613813779870;
    
    uint256 constant IC1x = 104303511713631756033518866914942786001711798454166272531789186175869488982;
    uint256 constant IC1y = 8973712959106563394634676112935305148390192961976480085891428240280814718444;
    
    uint256 constant IC2x = 1474972730240128711155241002644974523768290891724372861488573340197113726517;
    uint256 constant IC2y = 18363953281976288441654985152873063654323518999934401309522775823258915260831;
    
    uint256 constant IC3x = 5072038632443708654555079345293973047050502859878969388592711785377606449191;
    uint256 constant IC3y = 5185405550907789801276035127357289746950861744497584159301742165998073721729;
    
    uint256 constant IC4x = 16208371963358922690640507078993403242266578968299409174901447381960561748294;
    uint256 constant IC4y = 1153754788232226077616588360987431714563126734607086308287563584648044739195;
    
    uint256 constant IC5x = 18799430388722154968409612746222738106198472781731273517963225866069028240669;
    uint256 constant IC5y = 335461731056597103090905445315143587096509670498922693392136292646480642243;
    
    uint256 constant IC6x = 12481798419727048716653925865082612256548014744749248349396257802142929633434;
    uint256 constant IC6y = 8867501668153728110593040796067196112812279521575428337175805143782594044706;
    
    uint256 constant IC7x = 9432117681397013061431257085493060875589957634110994112662453736753378736525;
    uint256 constant IC7y = 9618743238537330786082964666086795799701514302146104889399090078598447918012;
    
    uint256 constant IC8x = 4785635526811221669893303058928757810818362497573567179214488893581556015934;
    uint256 constant IC8y = 1469646332117852018131453460092353815160084488029331686289963252581384844769;
    
    uint256 constant IC9x = 12494367896914635207319032838919740797467362876399384711577984501525330191141;
    uint256 constant IC9y = 9609038230209581945092499919503229158656849570373768679866887248936106209319;
    
    uint256 constant IC10x = 5678354832107574049260365379491855111012074870410480681594601883929808946915;
    uint256 constant IC10y = 10408100716384400201062313947572655442430260245651111802776517978341782485208;
    
    uint256 constant IC11x = 19837817399664915426352211353299443115462850422062014984942083682304897784473;
    uint256 constant IC11y = 15967278309869420674822371784325189437272937401142737547724708272536792047330;
    
    uint256 constant IC12x = 20249213855290665600126227725667579700596547809540686633841259198525198398951;
    uint256 constant IC12y = 7749802829518444554686240219272459531939742263107147747970265927713077482311;
    
    uint256 constant IC13x = 7570321671160775341211916858974130303592379605852981400475697323082432630941;
    uint256 constant IC13y = 1557192378668497901098130395872118987088856616433461653014302890958892769909;
    
    uint256 constant IC14x = 1138792849435987170706072788718532343721967217778926581696404449152672204514;
    uint256 constant IC14y = 9920489630012178367928962165964902087465620577906415779383917283859322969051;
    
    uint256 constant IC15x = 2754850553258391815587969329219657239902187839774009442213897582011737106021;
    uint256 constant IC15y = 3938689713966880951215579761725637953505168893923763367905752438469650090765;
    
    uint256 constant IC16x = 6450883314929092780954476715376315288100498516007036036950045644692983917302;
    uint256 constant IC16y = 18870208667124034734470715777316205678974734414929318668551237526692940120858;
    
    uint256 constant IC17x = 13609686935974826391838244318342937328475974815613003426417142509045238542271;
    uint256 constant IC17y = 3237485074422882791981310238634611006005755248153432111796264220617625646303;
    
    uint256 constant IC18x = 19862569176164431238556742470954820517144426377197999796978315310439741421801;
    uint256 constant IC18y = 18172198059233065414224008053936564015588948298658337372173622504077265087406;
    
    uint256 constant IC19x = 4425066096388247400265793882980147029927841420648941386622399871874461372171;
    uint256 constant IC19y = 8415098895308577290775545819433488002789327826285747087711972447791538456567;
    
    uint256 constant IC20x = 1028255664732678564059801950511758557183292412017108895922439449995643068366;
    uint256 constant IC20y = 11257121239950646996745605438638224721112283905657939806571836056548674196560;
    
    uint256 constant IC21x = 17359263330344396452518914491262334177621057382092956002053574018445529368198;
    uint256 constant IC21y = 16012311210143984833410749495260631128937651931647547026656656505994158136638;
    
    uint256 constant IC22x = 3019508709277746316019802181018005221855812572457809349906119287977837766815;
    uint256 constant IC22y = 7711552169407195411747212660443736846310299455490025351178521523854685031705;
    
    uint256 constant IC23x = 16377955251427372199407969141944089937638138693342483140850881275477468700085;
    uint256 constant IC23y = 16933625697044974188696106604662679594154014594422748739890329400941280420733;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[23] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
