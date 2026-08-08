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

	/// Convenience method for a pairing check for four pairs.
	function pairingProd4(
			G1Point memory a1, G2Point memory a2,
			G1Point memory b1, G2Point memory b2,
			G1Point memory c1, G2Point memory c2,
			G1Point memory d1, G2Point memory d2
	) view internal returns (bool) {
		G1Point[] memory p1 = new G1Point[](4);
		G2Point[] memory p2 = new G2Point[](4);
		p1[0] = a1;
		p1[1] = b1;
		p1[2] = c1;
		p1[3] = d1;
		p2[0] = a2;
		p2[1] = b2;
		p2[2] = c2;
		p2[3] = d2;
		return pairing(p1, p2);
	}

    function pairingProd5(
			G1Point memory a1, G2Point memory a2,
			G1Point memory b1, G2Point memory b2,
			G1Point memory c1, G2Point memory c2,
			G1Point memory d1, G2Point memory d2,
            G1Point memory e1, G2Point memory e2
	) view internal returns (bool) {
		G1Point[] memory p1 = new G1Point[](5);
		G2Point[] memory p2 = new G2Point[](5);
		p1[0] = a1;
		p1[1] = b1;
		p1[2] = c1;
		p1[3] = d1;
        p1[4] = e1;
		p2[0] = a2;
		p2[1] = b2;
		p2[2] = c2;
		p2[3] = d2;
        p2[4] = e2;
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

	function modInv(uint256 a, uint256 n) internal view returns (uint256 result) {
        bool success;
        assembly {
            let freemem := mload(0x40)
            mstore(freemem, 0x20)
            mstore(add(freemem,0x20), 0x20)
            mstore(add(freemem,0x40), 0x20)
            mstore(add(freemem,0x60), a)
            mstore(add(freemem,0x80), sub(n, 2))
            mstore(add(freemem,0xA0), n)
            success := staticcall(sub(gas(), 2000), 5, freemem, 0xC0, freemem, 0x20)
			//success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            result := mload(freemem)
        }
        require(success);
    }

	// 2. 将 modPow 改为 view
	function modPow(uint256 base, uint256 exponent, uint256 modulus) internal view returns (uint256) {
    	uint256[6] memory input = [32,32,32,base,exponent,modulus];
    	uint256[1] memory result;
    	assembly {
      	if iszero(staticcall(not(0), 0x05, input, 0xc0, result, 0x20)) {
        	revert(0, 0)
      			}
    	}
    	return result[0];
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

    function g1Equal(G1Point memory p1, G1Point memory p2) internal pure returns (bool)
    {
        return (p1.X == p2.X && p1.Y == p2.Y);
    }



//================================Access Policy========================================//

    struct Node {
        bool IsLeaf;
        uint256 Childrennum;
        uint256 T;
        uint256 Idx;
        bytes32 Attribute;
        uint256[] ChildrenIds;
    }

    struct NodeInput {
        uint256 Id;
        bool IsLeaf;
        uint256 Childrennum;
        uint256 T;
        uint256 Idx;
        bytes32 Attribute;
        uint256[] ChildrenIds;
    }


//========================================== RSCode ==========================================//

    /**
    * @dev 入口函数：接收序列化的策略数组和份额，进行即时验证
     */
    function RecurRSCode(NodeInput[] memory policy, G1Point[] memory shares) 
        public view returns (bool success) {
            require(policy.length > 0, "Policy is empty");
            require(shares.length > 0, "Shares is empty");

            // 1. 获取根节点 ID
            uint256 rootId = policy[0].Id;

            // 2. 启动递归验证
            // 直接把 policy 数组传进去，不再依赖 accessTree mapping
            (uint256 _consumed, G1Point memory _secret) = verifyRecursiveRS(rootId, policy, shares, 0);

            return true;
    }


    /**
    * @dev 递归验证主函数
    * @param nodeId 当前节点 ID
    * @param policy 完整的策略数组（用于查找当前节点信息）
    * @param shares 份额数组
    * @param shareIndex 当前份额索引
    */
    function verifyRecursiveRS(uint256 nodeId,NodeInput[] memory policy, G1Point[] memory shares,
        uint256 shareIndex) internal view returns (uint256 consumed, G1Point memory secret) {
    
            // 1. 在 policy 数组中查找当前节点
            // 注意：这里使用简单的线性搜索。如果树很大，这会比 mapping 慢，但对于验证逻辑是安全的。
            NodeInput memory node;
            bool found = false;
            for (uint256 i = 0; i < policy.length; i++) {
                if (policy[i].Id == nodeId) {
                    node = policy[i];
                    found = true;
                    break;
                }
            }
            require(found, "Node not found in policy");

            // 2. 叶子节点处理
            if (node.IsLeaf) {
                require(shareIndex < shares.length, "Insufficient shares");
                return (1, shares[shareIndex]);
            }

            // 3. 非叶子节点：递归收集子节点的 G1 秘密点
            // 使用 node.Childrennum 初始化数组
            G1Point[] memory childSecrets = new G1Point[](node.Childrennum);
            uint256 currentOffset = shareIndex;

            for (uint256 i = 0; i < node.Childrennum; i++) {
                // 确保子节点 ID 存在
                require(i < node.ChildrenIds.length, "Missing child ID");
        
                uint256 childConsumed;
                G1Point memory childSecret;
        
                // 递归调用：传入 policy 数组
                (childConsumed, childSecret) = verifyRecursiveRS(node.ChildrenIds[i], policy, shares, currentOffset);
                childSecrets[i] = childSecret;
                currentOffset += childConsumed;
            }

            uint256 n = node.Childrennum;
            uint256 k = node.T;

            require(n >= k, "Insufficient child secrets");

            // 4. 调用 RS 验证
            require(rscodeVerifyG1(childSecrets, k), "RS Code verification failed");

            // 5. 恢复当前节点的 G1 秘密点
            G1Point[] memory pointsToInterpolate = new G1Point[](k);
            for (uint256 i = 0; i < k; i++) {
                pointsToInterpolate[i] = childSecrets[i];
            }
    
            secret = interpolateG1(pointsToInterpolate);

            consumed = currentOffset - shareIndex;
    }

    /**
    * @dev RS 编码验证 (修正了 blockhash 依赖)
    */
    function rscodeVerifyG1(G1Point[] memory shares,uint256 k) 
        internal view returns (bool) {
            uint256 n = shares.length;

            if (n == k) {
                return true; 
            }
            if (n < k) {
                return false;
            }

            // ==========================================
            // 1. 生成确定性随机种子 (移除 blockhash 依赖)
            // ==========================================
            // 使用 shares 的内容作为种子，确保同样的输入永远生成同样的随机数
            uint256 seed = uint256(keccak256(abi.encodePacked(shares[0].X, shares[0].Y, n, k)));
    
            uint256 degF = n - k - 1;
            uint256[] memory fCoeffs = new uint256[](degF + 1);
    
            for (uint256 i = 0; i <= degF; i++) {
                fCoeffs[i] = uint256(keccak256(abi.encodePacked(seed, i))) % CURVE_ORDER;
            }

            // ==========================================
            // 2. 生成随机锚点 H1
            // ==========================================
            uint256 randScalar = uint256(keccak256(abi.encodePacked(seed, "H1_GENERATOR"))) % CURVE_ORDER;
            if (randScalar == 0) randScalar = 1;
    
            // 假设 G1Point(1, 2) 是生成元
            G1Point memory H1 = g1mul(G1Point(1, 2), randScalar);

            // ==========================================
            // 3. 计算对偶码字 cPerp
            // ==========================================
            uint256[] memory cPerp = new uint256[](n);

            for (uint256 i = 0; i < n; i++) {
                uint256 x_i = i + 1;
                uint256 denom = 1;
                for (uint256 j = 0; j < n; j++) {
                    if (i == j) continue;
                    uint256 x_j = j + 1;
                    uint256 diff;
                    if (x_i > x_j) {
                        diff = x_i - x_j;
                    } else {
                        diff = x_i + CURVE_ORDER - x_j;
                    }
                    denom = mulmod(denom, diff, CURVE_ORDER);
                }

                uint256 v_i = modInv(denom,CURVE_ORDER);
                uint256 fVal = evaluatePolynomial(fCoeffs, x_i, CURVE_ORDER);
                cPerp[i] = mulmod(v_i, fVal, CURVE_ORDER);
            }

            // ==========================================
            // 4. 验证 sum == H1
            // ==========================================
            G1Point memory sum = H1;
            for (uint256 i = 0; i < n; i++) {
            // 优化：如果系数为 0，跳过乘法
            if (cPerp[i] == 0) continue;
                G1Point memory term = g1mul(shares[i], cPerp[i]);
                sum = g1add(sum, term);
            }

            return (sum.X == H1.X && sum.Y == H1.Y);
            return true;
    }

    /**
    * @dev 拉格朗日插值恢复秘密点
    */
    function interpolateG1(G1Point[] memory points) 
        internal view returns (G1Point memory secret) {
            uint k = points.length;
            require(k > 0, "no points provided");
            secret = G1Point(0, 0);

            for (uint i = 0; i < k; i++) {
                uint x_i = i + 1;
                uint num = 1;
                uint den = 1;

            for (uint j = 0; j < k; j++) {
                if (i == j) continue;
                uint x_j = j + 1;
                num = mulmod(num, CURVE_ORDER - x_j, CURVE_ORDER);
                uint diff;
                if (x_i > x_j) {
                    diff = x_i - x_j;
                } else {
                    diff = x_i + CURVE_ORDER - x_j;
                }
                den = mulmod(den, diff, CURVE_ORDER);
            }

            uint denInv = modInv(den,CURVE_ORDER);
            uint coeff = mulmod(num, denInv, CURVE_ORDER);

            G1Point memory term = g1mul(points[i], coeff);
            secret = g1add(secret, term);
        }
        return secret;
    }

    /**
    * @dev 多项式求值
    */
    function evaluatePolynomial(uint256[] memory coefficients, uint256 x, uint256 order) 
        internal pure returns (uint256 result) 
    {
            result = coefficients[0];
            uint256 xPower = x;

            for (uint256 i = 1; i < coefficients.length; i++) {
                uint256 term = mulmod(coefficients[i], xPower, order);
                result = addmod(result, term, order);
                xPower = mulmod(xPower, x, order);
            }
        return result;
    }
//===============================================LSSS===============================================//
    function ReconG1(uint256[][] memory w, NodeInput[] memory _inputs, 
        G1Point[] memory shares, bytes32[] memory pathAttr) internal returns (G1Point memory) 
        {
            uint256 mapLength = _inputs.length;
            require(mapLength > 0, "ReconG1: Empty inputs");

            uint256[] memory I = new uint256[](mapLength); 
            uint256 validCount = 0;
            for (uint256 i = 0; i < mapLength; i++) {
                if (_inputs[i].IsLeaf) {
                    bytes32 targetAttr = _inputs[i].Attribute;
                    bool isInPathAttr = false;
                    for (uint k = 0; k < pathAttr.length; k++) {
                        if (pathAttr[k] == targetAttr) {
                            G1Point memory point = shares[k];
                            if (point.X != 0 || point.Y != 0) {
                                I[validCount] = i;
                                validCount++;
                            }
                            break;
                        }
                    }
        
                }
            }
            require(validCount > 0, "ReconG1: No valid shares found");

            uint256 rows = validCount;
            G1Point[][] memory shares2 = new G1Point[][](rows);
            for (uint256 i = 0; i < rows; i++) {
                shares2[i] = new G1Point[](1);
                //bytes32 attr = _inputs[I[i]].Attribute;
                shares2[i][0] = shares[I[i]];
            }

            G1Point[][] memory reconS = multiplyMatrixG1(w, shares2);
            return reconS[0][0];
    }

    function multiplyMatrixG1(uint256[][] memory A, G1Point[][] memory B) public view returns (G1Point[][] memory)
    {
        uint256 n = A.length;       
        uint256 m = A[0].length;    
        require(B.length == m, "Matrix dimensions mismatch: A cols != B rows");
    
        uint256 p = B[0].length;    
        G1Point[][] memory C = new G1Point[][](n);
        for (uint256 i = 0; i < n; i++) {
            C[i] = new G1Point[](p);
            for (uint256 j = 0; j < p; j++) {
                C[i][j] = G1Point(0, 0);
            }
        }

        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = 0; j < p; j++) {
                G1Point memory sumPoint = G1Point(0, 0);

                for (uint256 k = 0; k < m; k++) {
                    if (A[i][k] == 0) {
                        continue;
                    }
                    G1Point memory temp = g1mul(B[k][j], A[i][k]);
                    sumPoint = g1add(sumPoint, temp);
                }
                C[i][j] = sumPoint;
            }
        }
        return C;
    }

//=========================================DT Verification===========================================//
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
		Policy DTPolicy;
		G1Point Com;
		ABECiphertext C1;
		G1Point C2;
		G1Point C2Com;
		SubCiphertext C3;
	}

    struct Policy{
        mapping(uint256 => Node) root;
        uint256[][] W;
    }
 

	struct ABECiphertext{
		G1Point Com;
		Policy BuyPolicy;
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


	bool verABE=false;
	function UploadABECipher(uint256[][] memory w, NodeInput[] memory rowMap,
        bytes32[] memory pathAttr, NodeInput[] memory abePolicy, 
        G1Point memory abeCom, G1Point memory abeC, G2Point memory abe_C, 
        G1Point[] memory abeC1, G1Point[] memory abeC2, G1Point[] memory abeC3)public{
            //nx=2
            //Upload message:75989
            //Check Ciphertext
            //256333-75989=180344
            /*
			if (pairingProd3(g1neg(abeC),Mpk.G2,abeCom,Mpk.H2,Mpk.AlphaG1,abe_C)==false){
				return;
			}
            //190512-75989=114523
            if (RecurRSCode(abePolicy, abeC3)==false){
                return;
            }
            //759553-75989=683564
			for (uint i = 0; i < abeC1.length; i++) {
				if (pairingProd3(g1neg(abeC1[i]),Mpk.G2,abeC3[i],abe_C,g1neg(abeC2[i]),Mpk.HXsG2[rowMap[i].Attribute])==false){
			        return;
		        }
        	}
            //105018-75989=29029
            G1Point memory recoverSecret=ReconG1(w,rowMap,abeC3,pathAttr);
            if (g1Equal(recoverSecret,Mpk.H1)==false){
                return;
            }
            verABE=true;
            */
            //Store Ciphertext
            //1533555
            for (uint256 i = 0; i < abePolicy.length; i++) {
                NodeInput memory n = abePolicy[i];
                Cipher.C1.BuyPolicy.root[n.Idx] = Node({
                    IsLeaf: n.IsLeaf,
                    Childrennum: n.Childrennum,
                    T: n.T,
                    Idx: n.Idx,
                    Attribute: n.Attribute,
                    ChildrenIds: n.ChildrenIds
                });
            }
            uint256 rows = w.length;
            Cipher.C1.BuyPolicy.W = new uint256[][](rows);
            for (uint i = 0; i < rows; i++) {
                uint256 cols = w[i].length;
                Cipher.C1.BuyPolicy.W[i] = new uint256[](cols);
                for (uint j = 0; j < cols; j++) {
                    Cipher.C1.BuyPolicy.W[i][j] = w[i][j]; 
                }
            }
            Cipher.C1.Com=abeCom;
			Cipher.C1.C=abeC;
			Cipher.C1._C=abe_C;
            for (uint i = 0; i < abeC1.length; i++){
                Cipher.C1.C1[rowMap[i].Attribute]=abeC1[i];
            	Cipher.C1.C2[rowMap[i].Attribute]=abeC2[i];
				Cipher.C1.C3[rowMap[i].Attribute]=abeC3[i];
            }
            return;
	}
	function GetABEResult() public view returns (bool) {
        return verABE;
    }
 
    bool verPay = false;
	function UploadPayCipher(NodeInput[] memory tradePolicy,uint256[][] memory tradeW, 
        G1Point memory com, G1Point memory c2, G1Point memory c2Com, 
        G1Point memory c3Com,G1Point memory subC1,G2Point memory subC2)public{
            /*
            if (pairingProd2(g1neg(c2),Mpk.G2,c2Com,Vko)==false){
				return;
			}
            if (pairingProd3(g1neg(subC1),Mpk.G2,c3Com,Mpk.H2,Spk,subC2)==false){
                return;
            }
            G1Point[] memory tradeShares = new G1Point[](3); 
            tradeShares[0]=Cipher.C1.Com;
            tradeShares[1]=c2Com;
            tradeShares[2]=c3Com;
            if (RecurRSCode(tradePolicy, tradeShares)==false){
                return;
            }
            G1Point memory recoverSecret=g1add(g1mul(Cipher.C1.Com, tradeW[0][0]), g1mul(c2Com, tradeW[0][1]));
            if (g1Equal(recoverSecret,com)==false){
                return;
            }
            verPay=true;
            */
            
            for (uint256 i = 0; i < tradePolicy.length; i++) {
                NodeInput memory n = tradePolicy[i];
                Cipher.DTPolicy.root[n.Idx] = Node({
                    IsLeaf: n.IsLeaf,
                    Childrennum: n.Childrennum,
                    T: n.T,
                    Idx: n.Idx,
                    Attribute: n.Attribute,
                    ChildrenIds: n.ChildrenIds
                });
            }
            uint256 rows = tradeW.length;
            Cipher.DTPolicy.W = new uint256[][](rows);
            for (uint i = 0; i < rows; i++) {
                uint256 cols = tradeW[i].length;
                Cipher.DTPolicy.W[i] = new uint256[](cols);
                for (uint j = 0; j < cols; j++) {
                    Cipher.DTPolicy.W[i][j] = tradeW[i][j]; 
                }
            }
			Cipher.Com=com;
            Cipher.C2=c2;
			Cipher.C2Com=c2Com;
			Cipher.C3.Com=c3Com;
			Cipher.C3.C1=subC1;
			Cipher.C3.C2=subC2;
            return;
	}
    function GetPayResult() public view returns (bool) {
        return verPay;
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
			if (pairingProd3(g1neg(sk1), Mpk.G2, Spk, Mpk.U2, sk2, Vku)==true){
				verSK=true;
			}
			return;
	}
	function GetSKResult() public view returns (bool) {
        return verSK;
    }
//==============================================Trade=========================================//
    struct Product {
        uint256 price;
        string description;
    }
    uint256 public subFee = 0.01 ether;
    mapping(uint256 => mapping(address => Product)) public productList;
    mapping(address => mapping(address => mapping(uint256 => uint256))) public perPay;
    mapping(address => mapping(address => uint256)) public subPay;

    function Sale(uint256 PID, uint256 price, string memory description) public returns (bool) {
        // productList[PID][msg.sender] = product{price, description}
        productList[PID][msg.sender] = Product(price, description);
        return true;
    }

    function PayPer(address sellerAddr, uint256 PID) public payable returns (bool) {
        uint256 amount = productList[PID][sellerAddr].price;
        // assert(msg.value == amount)
        require(msg.value == amount, "Incorrect payment amount");
        // perPay[msg.sender][sellerAddr][PID] = msg.value
        perPay[msg.sender][sellerAddr][PID] = msg.value;
        return true;
    }

    function PerWithdraw(address buyAddr, uint256 PID) public returns (bool) {
        // amount = perPay[buyAddr][msg.sender][PID]
        uint256 amount = perPay[buyAddr][msg.sender][PID];
        // assert(amount > 0)
        require(amount > 0, "No balance to withdraw");
        // msg.sender.transfer(amount)
        payable(msg.sender).transfer(amount);
        // perPay[buyAddr][msg.sender][PID] = 0
        perPay[buyAddr][msg.sender][PID] = 0;
        return true;
    }

    function Subscribe(address sellerAddr) public payable returns (bool) {
        // assert(msg.value == subFee)
        require(msg.value == subFee, "Incorrect subscription fee");
        // subPay[msg.sender][sellerAddr] = msg.value
        subPay[msg.sender][sellerAddr] = msg.value;
        return true;
    }

    function SubWithdraw(address buyAddr) public returns (bool) {
        // amount = subPay[buyAddr][msg.sender]
        uint256 amount = subPay[buyAddr][msg.sender];
        // assert(amount > 0)
        require(amount > 0, "No subscription balance");
        // msg.sender.transfer(amount)
        payable(msg.sender).transfer(amount);
        // perPay[buyAddr][msg.sender][PID] = 0 (注意：伪代码此处可能是笔误，应该是 subPay 清零)
        subPay[buyAddr][msg.sender] = 0;
        return true;
    }
}


/*
    function cipherCheck(
        NodeInput[] memory _policyInputs,
        uint256 _pathId,
        G1Point memory _mpkH1,
        mapping(bytes32 => G1Point) memory _c3
    )
        public
        view
        returns (bool)
    {
        // 1. 重建策略树
        // 将扁平数组恢复到 accessTree mapping 中，并获取根节点对象
        Node memory root = _rebuildTree(_policyInputs);

        // 2. 获取路径节点
        // 从重建好的树中取出路径节点
        Node memory pathNode = accessTree[_pathId];

        // 3. 执行验证逻辑
        // 这里的逻辑和之前一样，只是现在数据已经在 mapping 里准备好了
        bytes32[] memory attrSet = rowToAttrib(pathNode);
        
        // 复用 _c3 映射作为 Q
        mapping(bytes32 => G1Point) storage Q = _c3;

        // 调用 ReconG1 进行重构
        // 注意：ReconG1 依赖 accessTree 里的数据，所以必须先执行 _rebuildTree
        G1Point memory recoverResult = ReconG1(root, Q);

        // 比对结果
        if (!g1Equal(recoverResult, _mpkH1)) {
            return false;
        }

        return true;
    }

    function rowToAttrib(Node memory _node)
        public
        pure
        returns (bytes32[] memory)
    {
        // 如果是叶子节点，直接返回包含该属性的数组
        if (_node.IsLeaf) {
            bytes32[] memory leafAttribs = new bytes32[](1);
            leafAttribs[0] = _node.Attribute;
            return leafAttribs;
        }

        // 如果是非叶子节点，递归收集所有子节点的属性
        // 1. 先统计子节点属性总数，以便分配数组大小
        uint256 totalLen = 0;
        for (uint256 i = 0; i < _node.ChildrenIds.length; i++) {
            // 这里需要访问 accessTree mapping 来获取子节点的完整信息
            // 假设这个函数是在 AccessTree 合约内部，或者传入了 mapping 引用
            // 为了演示，假设我们有一个内部函数能根据 ID 获取 Node
            // 注意：在实际合约中，你需要确保能访问到 accessTree
             // 这里的逻辑稍微有点绕，因为我们需要两次遍历：
             // 第一次算长度，第二次填数据。或者使用动态数组（比较耗Gas）。
             // 为了简化，我们假设有一个内部辅助函数 _getNode(id)
        }
        
        // --- 优化方案：使用内部递归辅助函数 ---
        // 为了避免两次遍历和复杂的内存管理，我们定义一个内部函数
        return _dfsAttribs(_node);
    }


    function _dfsAttribs(Node memory _node)
        internal
        view // 需要 view 来读取 accessTree mapping
        returns (bytes32[] memory)
    {
        // 1. 如果是叶子节点
        if (_node.IsLeaf) {
            bytes32[] memory result = new bytes32[](1);
            result[0] = _node.Attribute;
            return result;
        }

        // 2. 如果是非叶子节点，收集所有子节点的属性
        // 我们需要先计算总长度，因为 Solidity 内存数组创建时需要定长
        uint256 totalCount = 0;
        
        // 临时存储子节点的属性数组，用于后续合并
        bytes32[][] memory childrenAttribs = new bytes32[][](_node.ChildrenIds.length);

        for (uint256 i = 0; i < _node.ChildrenIds.length; i++) {
            // 从 mapping 中获取子节点
            Node memory childNode = accessTree[_node.ChildrenIds[i]];
            
            // 递归调用
            childrenAttribs[i] = _dfsAttribs(childNode);
            
            // 累加长度
            totalCount += childrenAttribs[i].length;
        }

        // 3. 合并所有子数组
        bytes32[] memory result = new bytes32[](totalCount);
        uint256 currentIndex = 0;

        for (uint256 i = 0; i < childrenAttribs.length; i++) {
            for (uint256 j = 0; j < childrenAttribs[i].length; j++) {
                result[currentIndex] = childrenAttribs[i][j];
                currentIndex++;
            }
        }

        return result;
    }

    function multiplyMatrix(uint256[][] memory A, uint256[][] memory B)
        public
        pure
        returns (uint256[][] memory)
    {
        uint256 n = A.length;       // A 的行数
        uint256 m = A[0].length;    // A 的列数
        uint256 p = B[0].length;    // B 的列数

        // 1. 维度检查：A 的列数必须等于 B 的行数
        require(B.length == m, "Matrix dimensions mismatch: A cols != B rows");

        // 2. 初始化结果矩阵 C (n x p)
        uint256[][] memory C = new uint256[][](n);
        for (uint256 i = 0; i < n; i++) {
            C[i] = new uint256[](p);
            // Solidity 新建数组默认值为 0，所以不需要显式初始化为 0
        }

        // 3. 矩阵乘法核心逻辑
        // C[i][j] = sum(A[i][k] * B[k][j])
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = 0; j < p; j++) {
                uint256 sum = 0;
                for (uint256 k = 0; k < m; k++) {
                    // 使用 mulmod 防止溢出并自动取模
                    // sum += (A[i][k] * B[k][j]) % CURVE_ORDER
                    sum = addmod(sum, mulmod(A[i][k], B[k][j], CURVE_ORDER), CURVE_ORDER);
                }
                C[i][j] = sum;
            }
        }

        return C;
    }

  
    function gaussJordanInverse(uint256[][] memory A)
        public
        view // 因为调用了 modInv (view)
        returns (uint256[][] memory)
    {
        uint256 n = A.length;
        require(n > 0, "Matrix is empty");

        // 1. 检查是否为方阵
        for (uint256 i = 0; i < n; i++) {
            require(A[i].length == n, "Matrix must be square");
        }

        // 2. 创建增广矩阵 [A | I]
        // 维度 n x 2n
        uint256[][] memory augmented = new uint256[][](n);
        for (uint256 i = 0; i < n; i++) {
            augmented[i] = new uint256[](2 * n);
            for (uint256 j = 0; j < n; j++) {
                // 左侧：复制 A
                augmented[i][j] = A[i][j];
                // 右侧：初始化为单位矩阵 I
                if (i == j) {
                    augmented[i][n + j] = 1;
                } else {
                    augmented[i][n + j] = 0;
                }
            }
        }

        // 3. 高斯-约旦消元
        for (uint256 i = 0; i < n; i++) {
            // --- 3.1 寻找主元 (Pivot) ---
            if (augmented[i][i] == 0) {
                bool found = false;
                for (uint256 j = i + 1; j < n; j++) {
                    if (augmented[j][i] != 0) {
                        // 交换行 i 和 j
                        _swapRows(augmented, i, j);
                        found = true;
                        break;
                    }
                }
                require(found, "Matrix is singular");
            }

            // --- 3.2 主元归一化 ---
            // inv = 1 / augmented[i][i]
            uint256 inv = modInv(augmented[i][i], CURVE_ORDER);
            
            for (uint256 j = 0; j < 2 * n; j++) {
                // augmented[i][j] = (augmented[i][j] * inv) % CURVE_ORDER
                augmented[i][j] = mulmod(augmented[i][j], inv, CURVE_ORDER);
            }

            // --- 3.3 消去其他行 ---
            for (uint256 j = 0; j < n; j++) {
                if (j != i) {
                    uint256 factor = augmented[j][i];
                    if (factor != 0) {
                        for (uint256 k = 0; k < 2 * n; k++) {
                            // augmented[j][k] = augmented[j][k] - factor * augmented[i][k]
                            uint256 val = mulmod(factor, augmented[i][k], CURVE_ORDER);
                            augmented[j][k] = submod(augmented[j][k], val);
                        }
                    }
                }
            }
        }

        // 4. 提取逆矩阵（右半部分）
        uint256[][] memory inverse = new uint256[][](n);
        for (uint256 i = 0; i < n; i++) {
            inverse[i] = new uint256[](n);
            for (uint256 j = 0; j < n; j++) {
                inverse[i][j] = augmented[i][n + j];
            }
        }

        return inverse;
    }

    // --- 内部辅助函数 ---

    function _swapRows(uint256[][] memory mat, uint256 r1, uint256 r2) internal pure {
        uint256[] memory temp = mat[r1];
        mat[r1] = mat[r2];
        mat[r2] = temp;
    }

    // 模拟 ExtractFirstThreshold 函数
    function _extractFirstThreshold(Node memory _node)
        internal
        pure
        returns (bool isThreshold, uint256 t, uint256 n, Node[] memory children)
    {
        if (_node.IsLeaf) {
            // 叶子节点不是阈值门
            return (false, 0, 0, new Node[](0));
        }
        // 返回门的信息和所有子节点
        return (true, _node.T, _node.Childrennum, _node.Children);
    }

    function convert(Node memory _root)
        public
        pure
        returns (int256[][] memory M, NodeInfo[] memory rowToNode)
    {
        // --- 1. 初始化变量 ---

        // L 存储当前的树结构片段
        Node[] memory L = new Node[](1);
        L[0] = _root;

        // M 存储矩阵，初始为 [[1]]
        M = new int256[][](1);
        M[0] = new int256[](1);
        M[0][0] = 1;

        // RowToNode 存储矩阵每一行对应的具体节点
        NodeInfo[] memory currentRowToNode = new NodeInfo[](1);
        currentRowToNode[0] = NodeInfo({IsLeaf: _root.IsLeaf, Attribute: _root.Attribute});

        uint256 m = 1; // 当前行数
        uint256 d = 1; // 当前列数
        uint256 z = 1; // 控制循环的变量

        // --- 2. 主循环：不断展开阈值门 ---
        while (z != 0) {
            z = 0;
            uint256 i = 1;
            uint256 n;
            uint256 t;
            bool isThreshold;
            Node[] memory remainingStructure;

            // 2.1 寻找下一个需要展开的阈值门
            for (i = 1; i <= m && z == 0; i++) {
                Node memory currentNode = L[i - 1];
                (isThreshold, t, n, remainingStructure) = _extractFirstThreshold(currentNode);

                if (isThreshold) {
                    z = i; // 找到了，记录位置并跳出循环
                }
            }

            if (z != 0) {
                // 2.2 准备展开
                uint256 m2 = n; // 子节点数量
                uint256 d2 = t; // 门限值
                Node[] memory L2 = remainingStructure; // 子节点列表

                // 2.3 备份当前状态
                Node[] memory L1 = new Node[](m);
                for (uint256 k = 0; k < m; k++) {
                    L1[k] = L[k];
                }

                int256[][] memory M1 = new int256[][](m);
                for (uint256 k = 0; k < m; k++) {
                    M1[k] = new int256[](d);
                    for (uint256 l = 0; l < d; l++) {
                        M1[k][l] = M[k][l];
                    }
                }

                NodeInfo[] memory currentRowToNode1 = new NodeInfo[](m);
                for (uint256 k = 0; k < m; k++) {
                    currentRowToNode1[k] = currentRowToNode[k];
                }

                uint256 m1 = m;
                uint256 d1 = d;

                // 2.4 重新初始化 M, L 和 rowToNode
                uint256 newRows = m1 + m2 - 1;
                uint256 newCols = d1 + d2 - 1;

                M = new int256[][](newRows);
                L = new Node[](newRows);
                currentRowToNode = new NodeInfo[](newRows);

                for (uint256 k = 0; k < newRows; k++) {
                    M[k] = new int256[](newCols);
                    for (uint256 l = 0; l < newCols; l++) {
                        M[k][l] = 0;
                    }
                }

                // 2.5 填充数据

                // A. 展开点之前的行 (保持不变)
                for (uint256 u = 0; u < z - 1; u++) {
                    L[u] = L1[u];
                    currentRowToNode[u] = currentRowToNode1[u];
                    for (uint256 v = 0; v < d1; v++) {
                        M[u][v] = M1[u][v];
                    }
                }

                // B. 展开点本身的行 (被替换为子节点)
                for (uint256 u = z - 1; u < z + m2 - 1; u++) {
                    uint256 childIdx = u - (z - 1);
                    L[u] = L2[childIdx];
                    currentRowToNode[u] = NodeInfo({IsLeaf: L2[childIdx].IsLeaf, Attribute: L2[childIdx].Attribute});

                    for (uint256 v = 0; v < d1; v++) {
                        M[u][v] = M1[z - 1][v];
                    }
                    
                    // 计算并填充右侧的列
                    int256 a = int256((u + 1) - (z - 1));
                    int256 x = a;
                    for (uint256 v = d1; v < d1 + d2 - 1; v++) {
                        M[u][v] = x;
                        x = (x * a) % 1000000000000000000; // 对应 Go 代码中的模运算
                    }
                }

                // C. 展开点之后的行 (下移)
                for (uint256 u = z + m2 - 1; u < newRows; u++) {
                    uint256 srcIdx = u - m2 + 1;
                    L[u] = L1[srcIdx];
                    currentRowToNode[u] = currentRowToNode1[srcIdx];
                    for (uint256 v = 0; v < d1; v++) {
                        M[u][v] = M1[srcIdx][v];
                    }
                }

                m = newRows;
                d = newCols;
            }
        }
        
        rowToNode = currentRowToNode;
    }



 function _extractFirstThreshold(uint256 _nodeId) 
        internal 
        view 
        returns (bool isThreshold, uint256 t, uint256 n, uint256[] memory childrenIds) 
    {
        Node memory node = accessTree[_nodeId];

        // 1. 如果是叶子节点，返回 false，表示不是阈值门
        if (node.IsLeaf) {
            return (false, 0, 0, new uint256[](0));
        }

        // 2. 如果是非叶子节点，返回它的所有信息
        // 这表示我们找到了一个需要被“展开”的门
        return (true, node.T, node.Childrennum, node.ChildrenIds);
    }
*/

/*
    function ReconG1(uint256[][] memory w, NodeInput[] memory _inputs, 
        mapping(bytes32 => G1Point) storage shares, bytes32[] memory pathAttr) internal returns (G1Point memory) 
        {
            uint256 mapLength = _inputs.length;
            require(mapLength > 0, "ReconG1: Empty inputs");

            uint256[] memory I = new uint256[](mapLength); 
            uint256 validCount = 0;
            for (uint256 i = 0; i < mapLength; i++) {
                if (_inputs[i].IsLeaf) {
                    bytes32 targetAttr = _inputs[i].Attribute;
                    bool isInPathAttr = false;
                    for (uint k = 0; k < pathAttr.length; k++) {
                        if (pathAttr[k] == targetAttr) {
                            isInPathAttr = true;
                            break;
                        }
                    }
                    if (isInPathAttr) {
                        G1Point memory point = shares[targetAttr];
                        if (point.X != 0 || point.Y != 0) {
                            I[validCount] = i;
                            validCount++;
                        }
                    }
                }
            }
            require(validCount > 0, "ReconG1: No valid shares found");

            uint256 rows = validCount;
            G1Point[][] memory shares2 = new G1Point[][](rows);
            for (uint256 i = 0; i < rows; i++) {
                shares2[i] = new G1Point[](1);
                bytes32 attr = _inputs[I[i]].Attribute;
                shares2[i][0] = shares[attr];
            }
            G1Point[][] memory reconS = multiplyMatrixG1(w, shares2);
            return reconS[0][0];
    }
*/