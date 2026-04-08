// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Trade{
     uint256 constant FIELD_ORDER = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 constant CURVE_ORDER = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 constant GROUP_ORDER   = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant CURVE_B = 3;

    // a = (p+1) / 4
    uint256 constant CURVE_A = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;

    struct G1Point {
        uint X;
        uint Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }

    // (P+1) / 4
    function A() pure internal returns (uint256) {
        return CURVE_A;
    }

    function P() pure internal returns (uint256) {
        return FIELD_ORDER;
    }

    function N() pure internal returns (uint256) {
        return CURVE_ORDER;
    }

    /// return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }

	/// return the generator of G2
	function P2() pure internal returns (G2Point memory) {
		return G2Point(
			[11559732032986387107991004021392285783925812861821192530917403151452391805634,
			 10857046999023057135944570762232829481370756359578518086990519993285655852781],
			[4082367875863433681332203403145435568316851327593401208105741076214120093531,
			 8495653923123431417604973247489272438418190587263600148770280649306958101930]
		);
	}
    /// return the negation of p, i.e. p.add(p.negate()) should be zero.
	function g1neg(G1Point memory p) pure internal returns (G1Point memory) {
		// The prime q in the base field F_q for G1
		uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
		if (p.X == 0 && p.Y == 0)
			return G1Point(0, 0);
		return G1Point(p.X, q - (p.Y % q));
	}

    /// return the sum of two points of G1
    function g1add(G1Point memory p1, G1Point memory p2) view internal returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        // Use "invalid" to make gas estimation work
        //switch success case 0 { invalid }
        }
        require(success);
    }

    /// return the product of a point on G1 and a scalar, i.e.
    /// p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
    function g1mul(G1Point memory p, uint s) view internal returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        // Use "invalid" to make gas estimation work
        //switch success case 0 { invalid }
        }
        require(success);
    }



	function pairing(G1Point[] memory p1, G2Point[] memory p2) view internal returns (bool) {
		require(p1.length == p2.length);
		uint elements = p1.length;
		uint inputSize = elements * 6;
		uint[] memory input = new uint[](inputSize);
		for (uint i = 0; i < elements; i++)
		{
			input[i * 6 + 0] = p1[i].X;
			input[i * 6 + 1] = p1[i].Y;
			input[i * 6 + 2] = p2[i].X[0];
			input[i * 6 + 3] = p2[i].X[1];
			input[i * 6 + 4] = p2[i].Y[0];
			input[i * 6 + 5] = p2[i].Y[1];
		}
		uint[1] memory out;
		bool success;
		assembly {
			success := staticcall(sub(gas()	, 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require(success);
		return out[0] != 0;
	}

	/// Convenience method for a pairing check for two pairs.
	function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) view internal returns (bool) {
		G1Point[] memory p1 = new G1Point[](2);
		G2Point[] memory p2 = new G2Point[](2);
		p1[0] = a1;
		p1[1] = b1;
		p2[0] = a2;
		p2[1] = b2;
		return pairing(p1, p2);
	}

	/// Convenience method for a pairing check for three pairs.
	function pairingProd3(
			G1Point memory a1, G2Point memory a2,
			G1Point memory b1, G2Point memory b2,
			G1Point memory c1, G2Point memory c2
	) view internal returns (bool) {
		G1Point[] memory p1 = new G1Point[](3);
		G2Point[] memory p2 = new G2Point[](3);
		p1[0] = a1;
		p1[1] = b1;
		p1[2] = c1;
		p2[0] = a2;
		p2[1] = b2;
		p2[2] = c2;
		return pairing(p1, p2);
	}



    function submod(uint a, uint b) internal pure returns (uint){
        uint a_nn;

        if(a>b) {
            a_nn = a;
        } else {
            a_nn = a+CURVE_ORDER;
        }

        return addmod(a_nn - b, 0, CURVE_ORDER);
    }

    // Invert function, invert in group
    function inv(uint256 a, uint256 prime) public returns (uint256){
    	return modPow(a, prime-2, prime);
    }

    function modPow(uint256 base, uint256 exponent, uint256 modulus) internal returns (uint256) {
	    uint256[6] memory input = [32,32,32,base,exponent,modulus];
	    uint256[1] memory result;
	    assembly {
	      if iszero(call(not(0), 0x05, 0, input, 0xc0, result, 0x20)) {
	        revert(0, 0)
	      }
	    }
	    return result[0];
	}

//================================Access Policy========================================//
    struct Node {
        bool isLeaf;              
        uint256 threshold;       
        bytes32 attribute;        
        uint256[] childrenIds;    
	}

    struct NodeInput {
        uint256 id;              
        bool isLeaf;
        uint256 threshold;
        uint256 idx;             
        bytes32 attribute;
        uint256[] childrenIds;
    }
    mapping(uint256 => Node) public accessTree; 
    uint256 public rootNodeId;

    function uploadAccessTree(NodeInput[] memory _nodes) public {
        //require(!treeUploaded, "Access tree has already been uploaded");
        require(_nodes.length > 0, "Node array cannot be empty");

        for (uint i = 0; i < _nodes.length; i++) {
            NodeInput memory inputNode = _nodes[i];
            // 注意：这里可以添加更多校验逻辑，例如检查 ID 是否唯一、是否超出范围等
            // require(...);

            Cipher.C1.Policy[inputNode.id] = Node({
                isLeaf: inputNode.isLeaf,
                threshold: inputNode.threshold,
                attribute: inputNode.attribute,
                childrenIds: inputNode.childrenIds
            });
        }
    }

    function getNode(uint256 _nodeId) public view returns (bool, uint256, bytes32, uint256[] memory) {
        Node memory node = accessTree[_nodeId];
        return (node.isLeaf, node.threshold, node.attribute, node.childrenIds);
    }
    
    function getRootNode() public view returns (bool, uint256, bytes32, uint256[] memory) {
        return getNode(rootNodeId);
    }

//=========================================DT===========================================//
    struct MPK {
	    G1Point G1;
	    G2Point G2;   	
        G1Point U1;
	    G2Point U2; 
        G1Point H1;
	    G2Point H2; 
        G1Point AlphaG1;
        uint256 Order;
		mapping(bytes32 => G1Point)  HXsG1;
		mapping(bytes32 => G2Point)  HXsG2;
    }

	struct DTCiphertext{
		mapping(uint256 => Node) Policy;
		G1Point Com;
		ABECiphertext C1;
		G1Point C2;
		G1Point C2Com;
		SubCiphertext C3;
	}

	struct ABECiphertext{
		G1Point Com;
		mapping(uint256 => Node) Policy;
		G1Point C;
		G2Point _C;
		mapping(bytes32 => G1Point) C1;
		mapping(bytes32 => G1Point) C2;
		mapping(bytes32 => G1Point) C3;
	}

	struct SubCiphertext{
		G1Point Com;
		G1Point C1;
		G2Point C2;
	}

	MPK Mpk;
	G1Point Spk;
	G1Point Pko;
	G2Point Vko;
	G1Point Pku;
	G2Point Vku;
	DTCiphertext Cipher;


    function UploadMPK(G1Point memory g1, G2Point memory g2,
		G1Point memory u1, G2Point memory u2,
		G1Point memory h1, G2Point memory h2, 
		G1Point memory alphaG1, bytes32[] memory attrHxs, 
		G1Point[] memory hxsG1, G2Point[] memory hxsG2) public {
        	Mpk.G1=g1;
			Mpk.G2=g2;
			Mpk.U1=u1;
			Mpk.U2=u2;
			Mpk.H1=h1;
			Mpk.H2=h2;
			Mpk.AlphaG1=alphaG1;
    		for (uint i = 0; i < attrHxs.length; i++) {
            	Mpk.HXsG1[attrHxs[i]]=hxsG1[i];
            	Mpk.HXsG2[attrHxs[i]]=hxsG2[i];
        	}
    }

	function UploadSPK(G1Point memory gammaG1)public{
		Spk=gammaG1;
	}	

	function UploadPK(G1Point memory pko, G2Point memory vko,
			G1Point memory pku, G2Point memory vku)public{
		Pko=pko;
		Vko=vko;
		Pku=pku;
		Vku=vku;
	}

	function UploadABECipher(G1Point memory com, NodeInput[] memory abeNodes, G1Point memory abeCom, 
		G1Point memory abeC, G2Point memory abe_C, bytes32[] memory abeAttr, 
		G1Point[] memory abeC1, G1Point[] memory abeC2, G1Point[] memory abeC3)public{
			Cipher.Com=com;
			uploadAccessTree(abeNodes);
			Cipher.C1.Com=abeCom;
			Cipher.C1.C=abeC;
			Cipher.C1._C=abe_C;
			for (uint i = 0; i < abeAttr.length; i++) {
            	Cipher.C1.C1[abeAttr[i]]=abeC1[i];
            	Cipher.C1.C2[abeAttr[i]]=abeC2[i];
				Cipher.C1.C3[abeAttr[i]]=abeC3[i];
        	}
	}

	function UploadPayCipher(G1Point memory c2, G1Point memory c2Com, G1Point memory c3Com,
		G1Point memory subC1,G2Point memory subC2)public{
			Cipher.C2=c2;
			Cipher.C2Com=c2Com;
			Cipher.C3.Com=c3Com;
			Cipher.C3.C1=subC1;
			Cipher.C3.C2=subC2;
	}


	bool verRK=false;
	function ReKeyVer(G1Point memory d1,G1Point memory d2) public  {
			if (pairingProd3(g1neg(d2), Mpk.G2, Cipher.C2Com, Mpk.H2, d1, Vku)==true){
				verRK=true;
			}
			return;
	}
	function GetRKResult() public view returns (bool) {
        return verRK;
    }

	bool verSK=false;
	function SubKeyVer(G1Point memory sk1,G1Point memory sk2) public {
			if (pairingProd3(g1neg(sk1), Mpk.G2, Spk, Mpk.H2, sk2, Vku)==true){
				verSK=true;
			}
			return;
	}
	function GetSKResult() public view returns (bool) {
        return verSK;
    }

}