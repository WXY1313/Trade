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
//================================Access Policy========================================//

 //==================== Access Tree ====================//
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
mapping(uint256 => Node) internal accessTree;
// 假设 accessTree 已在全局定义
// mapping(uint256 => Node) internal accessTree;

//==================== RSCode ====================//

/**
 * @dev 入口函数：接收序列化的策略数组和份额，进行即时验证
 */
function RecurRSCode(
    NodeInput[] memory policy, 
    G1Point[] memory shares
) public view returns (bool success) {
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
function verifyRecursiveRS(
    uint256 nodeId,
    NodeInput[] memory policy, // <--- 新增：传入策略数组
    G1Point[] memory shares,
    uint256 shareIndex
) internal view returns (uint256 consumed, G1Point memory secret) {
    
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
function rscodeVerifyG1(
    G1Point[] memory shares,
    uint256 k
) internal view returns (bool) {
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

        uint256 v_i = inv(denom,CURVE_ORDER);
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
}

/**
 * @dev 拉格朗日插值恢复秘密点
 */
function interpolateG1(G1Point[] memory points) internal view returns (G1Point memory secret) {
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

        uint denInv = inv(den,CURVE_ORDER);
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
