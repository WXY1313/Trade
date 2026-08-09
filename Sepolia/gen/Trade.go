// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contract

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
	_ = time.Tick
	_ = context.Background
)

// TradeG1Point is an auto generated low-level Go binding around an user-defined struct.
type TradeG1Point struct {
	X *big.Int
	Y *big.Int
}

// TradeG2Point is an auto generated low-level Go binding around an user-defined struct.
type TradeG2Point struct {
	X [2]*big.Int
	Y [2]*big.Int
}

// TradeNodeInput is an auto generated low-level Go binding around an user-defined struct.
type TradeNodeInput struct {
	Id          *big.Int
	IsLeaf      bool
	Threshold   *big.Int
	Idx         *big.Int
	Attribute   [32]byte
	ChildrenIds []*big.Int
}

// ContractMetaData contains all meta data concerning the Contract contract.
var ContractMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"name\":\"GetRKResult\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"GetSKResult\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"d1\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"d2\",\"type\":\"tuple\"}],\"name\":\"ReKeyVer\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"sk1\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"sk2\",\"type\":\"tuple\"}],\"name\":\"SubKeyVer\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"com\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"id\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"isLeaf\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"threshold\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"idx\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"attribute\",\"type\":\"bytes32\"},{\"internalType\":\"uint256[]\",\"name\":\"childrenIds\",\"type\":\"uint256[]\"}],\"internalType\":\"structTrade.NodeInput[]\",\"name\":\"abeNodes\",\"type\":\"tuple[]\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"abeCom\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"abeC\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256[2]\",\"name\":\"X\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"Y\",\"type\":\"uint256[2]\"}],\"internalType\":\"structTrade.G2Point\",\"name\":\"abe_C\",\"type\":\"tuple\"},{\"internalType\":\"bytes32[]\",\"name\":\"abeAttr\",\"type\":\"bytes32[]\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point[]\",\"name\":\"abeC1\",\"type\":\"tuple[]\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point[]\",\"name\":\"abeC2\",\"type\":\"tuple[]\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point[]\",\"name\":\"abeC3\",\"type\":\"tuple[]\"}],\"name\":\"UploadABECipher\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"g1\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256[2]\",\"name\":\"X\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"Y\",\"type\":\"uint256[2]\"}],\"internalType\":\"structTrade.G2Point\",\"name\":\"g2\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"u1\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256[2]\",\"name\":\"X\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"Y\",\"type\":\"uint256[2]\"}],\"internalType\":\"structTrade.G2Point\",\"name\":\"u2\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"h1\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256[2]\",\"name\":\"X\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"Y\",\"type\":\"uint256[2]\"}],\"internalType\":\"structTrade.G2Point\",\"name\":\"h2\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"alphaG1\",\"type\":\"tuple\"},{\"internalType\":\"bytes32[]\",\"name\":\"attrHxs\",\"type\":\"bytes32[]\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point[]\",\"name\":\"hxsG1\",\"type\":\"tuple[]\"},{\"components\":[{\"internalType\":\"uint256[2]\",\"name\":\"X\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"Y\",\"type\":\"uint256[2]\"}],\"internalType\":\"structTrade.G2Point[]\",\"name\":\"hxsG2\",\"type\":\"tuple[]\"}],\"name\":\"UploadMPK\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"pko\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256[2]\",\"name\":\"X\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"Y\",\"type\":\"uint256[2]\"}],\"internalType\":\"structTrade.G2Point\",\"name\":\"vko\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"pku\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256[2]\",\"name\":\"X\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"Y\",\"type\":\"uint256[2]\"}],\"internalType\":\"structTrade.G2Point\",\"name\":\"vku\",\"type\":\"tuple\"}],\"name\":\"UploadPK\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"c2\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"c2Com\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"c3Com\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"subC1\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256[2]\",\"name\":\"X\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"Y\",\"type\":\"uint256[2]\"}],\"internalType\":\"structTrade.G2Point\",\"name\":\"subC2\",\"type\":\"tuple\"}],\"name\":\"UploadPayCipher\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structTrade.G1Point\",\"name\":\"gammaG1\",\"type\":\"tuple\"}],\"name\":\"UploadSPK\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"accessTree\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"isLeaf\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"threshold\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"attribute\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_nodeId\",\"type\":\"uint256\"}],\"name\":\"getNode\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"},{\"internalType\":\"uint256[]\",\"name\":\"\",\"type\":\"uint256[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getRootNode\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"},{\"internalType\":\"uint256[]\",\"name\":\"\",\"type\":\"uint256[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"prime\",\"type\":\"uint256\"}],\"name\":\"inv\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"rootNodeId\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"id\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"isLeaf\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"threshold\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"idx\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"attribute\",\"type\":\"bytes32\"},{\"internalType\":\"uint256[]\",\"name\":\"childrenIds\",\"type\":\"uint256[]\"}],\"internalType\":\"structTrade.NodeInput[]\",\"name\":\"_nodes\",\"type\":\"tuple[]\"}],\"name\":\"uploadAccessTree\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x60806040525f60425f6101000a81548160ff0219169083151502179055505f604260016101000a81548160ff0219169083151502179055503480156041575f5ffd5b5061254e8061004f5f395ff3fe608060405234801561000f575f5ffd5b50600436106100f3575f3560e01c80635ba5342a11610095578063918377e211610064578063918377e214610261578063996370821461027d578063c4fcb35714610299578063ef6bc912146102b5576100f3565b80635ba5342a146101ed57806363ca7a561461020b5780636922231214610227578063783660c914610245576100f3565b806330edd108116100d157806330edd1081461014d578063338255f31461016957806338d1fcc3146101995780634f0f4aa9146101ba576100f3565b80630be2ef69146100f757806319ae829a146101155780631f422ed714610131575b5f5ffd5b6100ff6102e7565b60405161010c9190611627565b60405180910390f35b61012f600480360381019061012a9190611ad7565b6102fd565b005b61014b60048036038101906101469190611c09565b61050c565b005b61016760048036038101906101629190611c82565b6105be565b005b610183600480360381019061017e9190611cc0565b6107e2565b6040516101909190611d0d565b60405180910390f35b6101a1610802565b6040516101b19493929190611dec565b60405180910390f35b6101d460048036038101906101cf9190611e36565b610820565b6040516101e49493929190611dec565b60405180910390f35b6101f56108e9565b6040516102029190611d0d565b60405180910390f35b61022560048036038101906102209190611c82565b6108ef565b005b61022f610b15565b60405161023c9190611627565b60405180910390f35b61025f600480360381019061025a9190611e61565b610b2a565b005b61027b6004803603810190610276919061210d565b610b45565b005b61029760048036038101906102929190612260565b610d28565b005b6102b360048036038101906102ae91906122c6565b610dc6565b005b6102cf60048036038101906102ca9190611e36565b610ee5565b6040516102de9392919061230d565b60405180910390f35b5f604260019054906101000a900460ff16905090565b8960025f015f820151815f01556020820151816001015590505088600280015f820151815f019060026103319291906114e5565b506020820151816002019060026103499291906114e5565b509050508760026006015f820151815f0155602082015181600101559050508660026008015f820151815f019060026103839291906114e5565b5060208201518160020190600261039b9291906114e5565b50905050856002600c015f820151815f015560208201518160010155905050846002600e015f820151815f019060026103d59291906114e5565b506020820151816002019060026103ed9291906114e5565b509050508360026012015f820151815f0155602082015181600101559050505f5f90505b83518110156104ff5782818151811061042d5761042c612342565b5b602002602001015160026015015f86848151811061044e5761044d612342565b5b602002602001015181526020019081526020015f205f820151815f01556020820151816001015590505081818151811061048b5761048a612342565b5b602002602001015160026016015f8684815181106104ac576104ab612342565b5b602002602001015181526020019081526020015f205f820151815f019060026104d69291906114e5565b506020820151816002019060026104ee9291906114e5565b509050508080600101915050610411565b5050505050505050505050565b846027600f015f820151815f0155602082015181600101559050508360276011015f820151815f0155602082015181600101559050508260276013015f015f820151815f0155602082015181600101559050508160276013016002015f820151815f0155602082015181600101559050508060276013016004015f820151815f0190600261059b9291906114e5565b506020820151816002019060026105b39291906114e5565b509050505050505050565b600115156107bb6105ce84610f16565b600280016040518060400160405290815f8201600280602002604051908101604052809291908260028015610618576020028201915b815481526020019060010190808311610604575b505050505081526020016002820160028060200260405190810160405280929190826002801561065d576020028201915b815481526020019060010190808311610649575b50505050508152505060196040518060400160405290815f82015481526020016001820154815250506002600e016040518060400160405290815f82016002806020026040519081016040528092919082600280156106d1576020028201915b8154815260200190600101908083116106bd575b5050505050815260200160028201600280602002604051908101604052809291908260028015610716576020028201915b815481526020019060010190808311610702575b5050505050815250508660236040518060400160405290815f8201600280602002604051908101604052809291908260028015610768576020028201915b815481526020019060010190808311610754575b50505050508152602001600282016002806020026040519081016040528092919082600280156107ad576020028201915b815481526020019060010190808311610799575b505050505081525050610fb4565b1515036107de576001604260016101000a81548160ff0219169083151502179055505b5050565b5f6107fa836002846107f4919061239c565b8461113b565b905092915050565b5f5f5f6060610812600154610820565b935093509350935090919293565b5f5f5f60605f5f5f8781526020019081526020015f206040518060800160405290815f82015f9054906101000a900460ff161515151581526020016001820154815260200160028201548152602001600382018054806020026020016040519081016040528092919081815260200182805480156108bb57602002820191905f5260205f20905b8154815260200190600101908083116108a7575b5050505050815250509050805f01518160200151826040015183606001519450945094509450509193509193565b60015481565b60011515610aef6108ff83610f16565b600280016040518060400160405290815f8201600280602002604051908101604052809291908260028015610949576020028201915b815481526020019060010190808311610935575b505050505081526020016002820160028060200260405190810160405280929190826002801561098e576020028201915b81548152602001906001019080831161097a575b50505050508152505060276011016040518060400160405290815f82015481526020016001820154815250506002600e016040518060400160405290815f8201600280602002604051908101604052809291908260028015610a05576020028201915b8154815260200190600101908083116109f1575b5050505050815260200160028201600280602002604051908101604052809291908260028015610a4a576020028201915b815481526020019060010190808311610a36575b5050505050815250508760236040518060400160405290815f8201600280602002604051908101604052809291908260028015610a9c576020028201915b815481526020019060010190808311610a88575b5050505050815260200160028201600280602002604051908101604052809291908260028015610ae1576020028201915b815481526020019060010190808311610acd575b505050505081525050610fb4565b151503610b1157600160425f6101000a81548160ff0219169083151502179055505b5050565b5f60425f9054906101000a900460ff16905090565b8060195f820151815f01556020820151816001015590505050565b8860276001015f820151815f015560208201518160010155905050610b6988610dc6565b8660276003015f015f820151815f0155602082015181600101559050508560276003016003015f820151815f0155602082015181600101559050508460276003016005015f820151815f01906002610bc29291906114e5565b50602082015181600201906002610bda9291906114e5565b509050505f5f90505b8451811015610d1c57838181518110610bff57610bfe612342565b5b602002602001015160276003016009015f878481518110610c2357610c22612342565b5b602002602001015181526020019081526020015f205f820151815f015560208201518160010155905050828181518110610c6057610c5f612342565b5b60200260200101516027600301600a015f878481518110610c8457610c83612342565b5b602002602001015181526020019081526020015f205f820151815f015560208201518160010155905050818181518110610cc157610cc0612342565b5b60200260200101516027600301600b015f878481518110610ce557610ce4612342565b5b602002602001015181526020019081526020015f205f820151815f0155602082015181600101559050508080600101915050610be3565b50505050505050505050565b83601b5f820151815f01556020820151816001015590505082601d5f820151815f01906002610d589291906114e5565b50602082015181600201906002610d709291906114e5565b509050508160215f820151815f0155602082015181600101559050508060235f820151815f01906002610da49291906114e5565b50602082015181600201906002610dbc9291906114e5565b5090505050505050565b5f815111610e09576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610e0090612429565b60405180910390fd5b5f5f90505b8151811015610ee1575f828281518110610e2b57610e2a612342565b5b60200260200101519050604051806080016040528082602001511515815260200182604001518152602001826080015181526020018260a0015181525060276003016002015f835f015181526020019081526020015f205f820151815f015f6101000a81548160ff02191690831515021790555060208201518160010155604082015181600201556060820151816003019080519060200190610ecf929190611525565b50905050508080600101915050610e0e565b5050565b5f602052805f5260405f205f91509050805f015f9054906101000a900460ff16908060010154908060020154905083565b610f1e611570565b5f7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4790505f835f0151148015610f5757505f8360200151145b15610f795760405180604001604052805f81526020015f815250915050610faf565b6040518060400160405280845f01518152602001828560200151610f9d9190612474565b83610fa8919061239c565b8152509150505b919050565b5f5f600367ffffffffffffffff811115610fd157610fd0611665565b5b60405190808252806020026020018201604052801561100a57816020015b610ff7611570565b815260200190600190039081610fef5790505b5090505f600367ffffffffffffffff81111561102957611028611665565b5b60405190808252806020026020018201604052801561106257816020015b61104f611588565b8152602001906001900390816110475790505b50905088825f8151811061107957611078612342565b5b6020026020010181905250868260018151811061109957611098612342565b5b602002602001018190525084826002815181106110b9576110b8612342565b5b602002602001018190525087815f815181106110d8576110d7612342565b5b602002602001018190525085816001815181106110f8576110f7612342565b5b6020026020010181905250838160028151811061111857611117612342565b5b602002602001018190525061112d82826111ae565b925050509695505050505050565b5f5f6040518060c001604052806020815260200160208152602001602081526020018681526020018581526020018481525090506111776115ae565b60208160c0845f60055f19f161118b575f5ffd5b805f6001811061119e5761119d612342565b5b6020020151925050509392505050565b5f81518351146111bc575f5ffd5b5f835190505f6006826111cf91906124a4565b90505f8167ffffffffffffffff8111156111ec576111eb611665565b5b60405190808252806020026020018201604052801561121a5781602001602082028036833780820191505090505b5090505f5f90505b838110156114955786818151811061123d5761123c612342565b5b60200260200101515f0151825f60068461125791906124a4565b61126191906124e5565b8151811061127257611271612342565b5b60200260200101818152505086818151811061129157611290612342565b5b6020026020010151602001518260016006846112ad91906124a4565b6112b791906124e5565b815181106112c8576112c7612342565b5b6020026020010181815250508581815181106112e7576112e6612342565b5b60200260200101515f01515f6002811061130457611303612342565b5b602002015182600260068461131991906124a4565b61132391906124e5565b8151811061133457611333612342565b5b60200260200101818152505085818151811061135357611352612342565b5b60200260200101515f015160016002811061137157611370612342565b5b602002015182600360068461138691906124a4565b61139091906124e5565b815181106113a1576113a0612342565b5b6020026020010181815250508581815181106113c0576113bf612342565b5b6020026020010151602001515f600281106113de576113dd612342565b5b60200201518260046006846113f391906124a4565b6113fd91906124e5565b8151811061140e5761140d612342565b5b60200260200101818152505085818151811061142d5761142c612342565b5b60200260200101516020015160016002811061144c5761144b612342565b5b602002015182600560068461146191906124a4565b61146b91906124e5565b8151811061147c5761147b612342565b5b6020026020010181815250508080600101915050611222565b5061149e6115ae565b5f602082602086026020860160086107d05a03fa9050806114bd575f5ffd5b5f825f600181106114d1576114d0612342565b5b602002015114159550505050505092915050565b8260028101928215611514579160200282015b828111156115135782518255916020019190600101906114f8565b5b50905061152191906115d0565b5090565b828054828255905f5260205f2090810192821561155f579160200282015b8281111561155e578251825591602001919060010190611543565b5b50905061156c91906115d0565b5090565b60405180604001604052805f81526020015f81525090565b604051806040016040528061159b6115eb565b81526020016115a86115eb565b81525090565b6040518060200160405280600190602082028036833780820191505090505090565b5b808211156115e7575f815f9055506001016115d1565b5090565b6040518060400160405280600290602082028036833780820191505090505090565b5f8115159050919050565b6116218161160d565b82525050565b5f60208201905061163a5f830184611618565b92915050565b5f604051905090565b5f5ffd5b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b61169b82611655565b810181811067ffffffffffffffff821117156116ba576116b9611665565b5b80604052505050565b5f6116cc611640565b90506116d88282611692565b919050565b5f5ffd5b5f819050919050565b6116f3816116e1565b81146116fd575f5ffd5b50565b5f8135905061170e816116ea565b92915050565b5f6040828403121561172957611728611651565b5b61173360406116c3565b90505f61174284828501611700565b5f83015250602061175584828501611700565b60208301525092915050565b5f5ffd5b5f67ffffffffffffffff82111561177f5761177e611665565b5b602082029050919050565b5f5ffd5b5f6117a061179b84611765565b6116c3565b905080602084028301858111156117ba576117b961178a565b5b835b818110156117e357806117cf8882611700565b8452602084019350506020810190506117bc565b5050509392505050565b5f82601f83011261180157611800611761565b5b600261180e84828561178e565b91505092915050565b5f6080828403121561182c5761182b611651565b5b61183660406116c3565b90505f611845848285016117ed565b5f830152506040611858848285016117ed565b60208301525092915050565b5f67ffffffffffffffff82111561187e5761187d611665565b5b602082029050602081019050919050565b5f819050919050565b6118a18161188f565b81146118ab575f5ffd5b50565b5f813590506118bc81611898565b92915050565b5f6118d46118cf84611864565b6116c3565b905080838252602082019050602084028301858111156118f7576118f661178a565b5b835b81811015611920578061190c88826118ae565b8452602084019350506020810190506118f9565b5050509392505050565b5f82601f83011261193e5761193d611761565b5b813561194e8482602086016118c2565b91505092915050565b5f67ffffffffffffffff82111561197157611970611665565b5b602082029050602081019050919050565b5f61199461198f84611957565b6116c3565b905080838252602082019050604084028301858111156119b7576119b661178a565b5b835b818110156119e057806119cc8882611714565b8452602084019350506040810190506119b9565b5050509392505050565b5f82601f8301126119fe576119fd611761565b5b8135611a0e848260208601611982565b91505092915050565b5f67ffffffffffffffff821115611a3157611a30611665565b5b602082029050602081019050919050565b5f611a54611a4f84611a17565b6116c3565b90508083825260208201905060808402830185811115611a7757611a7661178a565b5b835b81811015611aa05780611a8c8882611817565b845260208401935050608081019050611a79565b5050509392505050565b5f82601f830112611abe57611abd611761565b5b8135611ace848260208601611a42565b91505092915050565b5f5f5f5f5f5f5f5f5f5f6102e08b8d031215611af657611af5611649565b5b5f611b038d828e01611714565b9a50506040611b148d828e01611817565b99505060c0611b258d828e01611714565b985050610100611b378d828e01611817565b975050610180611b498d828e01611714565b9650506101c0611b5b8d828e01611817565b955050610240611b6d8d828e01611714565b9450506102808b013567ffffffffffffffff811115611b8f57611b8e61164d565b5b611b9b8d828e0161192a565b9350506102a08b013567ffffffffffffffff811115611bbd57611bbc61164d565b5b611bc98d828e016119ea565b9250506102c08b013567ffffffffffffffff811115611beb57611bea61164d565b5b611bf78d828e01611aaa565b9150509295989b9194979a5092959850565b5f5f5f5f5f6101808688031215611c2357611c22611649565b5b5f611c3088828901611714565b9550506040611c4188828901611714565b9450506080611c5288828901611714565b93505060c0611c6388828901611714565b925050610100611c7588828901611817565b9150509295509295909350565b5f5f60808385031215611c9857611c97611649565b5b5f611ca585828601611714565b9250506040611cb685828601611714565b9150509250929050565b5f5f60408385031215611cd657611cd5611649565b5b5f611ce385828601611700565b9250506020611cf485828601611700565b9150509250929050565b611d07816116e1565b82525050565b5f602082019050611d205f830184611cfe565b92915050565b611d2f8161188f565b82525050565b5f81519050919050565b5f82825260208201905092915050565b5f819050602082019050919050565b611d67816116e1565b82525050565b5f611d788383611d5e565b60208301905092915050565b5f602082019050919050565b5f611d9a82611d35565b611da48185611d3f565b9350611daf83611d4f565b805f5b83811015611ddf578151611dc68882611d6d565b9750611dd183611d84565b925050600181019050611db2565b5085935050505092915050565b5f608082019050611dff5f830187611618565b611e0c6020830186611cfe565b611e196040830185611d26565b8181036060830152611e2b8184611d90565b905095945050505050565b5f60208284031215611e4b57611e4a611649565b5b5f611e5884828501611700565b91505092915050565b5f60408284031215611e7657611e75611649565b5b5f611e8384828501611714565b91505092915050565b5f67ffffffffffffffff821115611ea657611ea5611665565b5b602082029050602081019050919050565b611ec08161160d565b8114611eca575f5ffd5b50565b5f81359050611edb81611eb7565b92915050565b5f67ffffffffffffffff821115611efb57611efa611665565b5b602082029050602081019050919050565b5f611f1e611f1984611ee1565b6116c3565b90508083825260208201905060208402830185811115611f4157611f4061178a565b5b835b81811015611f6a5780611f568882611700565b845260208401935050602081019050611f43565b5050509392505050565b5f82601f830112611f8857611f87611761565b5b8135611f98848260208601611f0c565b91505092915050565b5f60c08284031215611fb657611fb5611651565b5b611fc060c06116c3565b90505f611fcf84828501611700565b5f830152506020611fe284828501611ecd565b6020830152506040611ff684828501611700565b604083015250606061200a84828501611700565b606083015250608061201e848285016118ae565b60808301525060a082013567ffffffffffffffff811115612042576120416116dd565b5b61204e84828501611f74565b60a08301525092915050565b5f61206c61206784611e8c565b6116c3565b9050808382526020820190506020840283018581111561208f5761208e61178a565b5b835b818110156120d657803567ffffffffffffffff8111156120b4576120b3611761565b5b8086016120c18982611fa1565b85526020850194505050602081019050612091565b5050509392505050565b5f82601f8301126120f4576120f3611761565b5b813561210484826020860161205a565b91505092915050565b5f5f5f5f5f5f5f5f5f6101e08a8c03121561212b5761212a611649565b5b5f6121388c828d01611714565b99505060408a013567ffffffffffffffff8111156121595761215861164d565b5b6121658c828d016120e0565b98505060606121768c828d01611714565b97505060a06121878c828d01611714565b96505060e06121988c828d01611817565b9550506101608a013567ffffffffffffffff8111156121ba576121b961164d565b5b6121c68c828d0161192a565b9450506101808a013567ffffffffffffffff8111156121e8576121e761164d565b5b6121f48c828d016119ea565b9350506101a08a013567ffffffffffffffff8111156122165761221561164d565b5b6122228c828d016119ea565b9250506101c08a013567ffffffffffffffff8111156122445761224361164d565b5b6122508c828d016119ea565b9150509295985092959850929598565b5f5f5f5f610180858703121561227957612278611649565b5b5f61228687828801611714565b945050604061229787828801611817565b93505060c06122a887828801611714565b9250506101006122ba87828801611817565b91505092959194509250565b5f602082840312156122db576122da611649565b5b5f82013567ffffffffffffffff8111156122f8576122f761164d565b5b612304848285016120e0565b91505092915050565b5f6060820190506123205f830186611618565b61232d6020830185611cfe565b61233a6040830184611d26565b949350505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6123a6826116e1565b91506123b1836116e1565b92508282039050818111156123c9576123c861236f565b5b92915050565b5f82825260208201905092915050565b7f4e6f64652061727261792063616e6e6f7420626520656d7074790000000000005f82015250565b5f612413601a836123cf565b915061241e826123df565b602082019050919050565b5f6020820190508181035f83015261244081612407565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61247e826116e1565b9150612489836116e1565b92508261249957612498612447565b5b828206905092915050565b5f6124ae826116e1565b91506124b9836116e1565b92508282026124c7816116e1565b915082820484148315176124de576124dd61236f565b5b5092915050565b5f6124ef826116e1565b91506124fa836116e1565b92508282019050808211156125125761251161236f565b5b9291505056fea26469706673582212205baaf1bd586f12c0f73ae8c65059378359374a2992a83f929ec457af4a2940ee64736f6c634300081c0033",
}

// ContractABI is the input ABI used to generate the binding from.
// Deprecated: Use ContractMetaData.ABI instead.
var ContractABI = ContractMetaData.ABI

// ContractBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ContractMetaData.Bin instead.
var ContractBin = ContractMetaData.Bin

// DeployContract deploys a new Ethereum contract, binding an instance of Contract to it.
func DeployContract(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Contract, error) {
	parsed, err := ContractMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ContractBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Contract{ContractCaller: ContractCaller{contract: contract}, ContractTransactor: ContractTransactor{contract: contract}, ContractFilterer: ContractFilterer{contract: contract}}, nil
}

// Contract is an auto generated Go binding around an Ethereum contract.
type Contract struct {
	ContractCaller     // Read-only binding to the contract
	ContractTransactor // Write-only binding to the contract
	ContractFilterer   // Log filterer for contract events
}

// ContractCaller is an auto generated read-only Go binding around an Ethereum contract.
type ContractCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ContractTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ContractFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ContractSession struct {
	Contract     *Contract         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ContractCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ContractCallerSession struct {
	Contract *ContractCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// ContractTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ContractTransactorSession struct {
	Contract     *ContractTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// ContractRaw is an auto generated low-level Go binding around an Ethereum contract.
type ContractRaw struct {
	Contract *Contract // Generic contract binding to access the raw methods on
}

// ContractCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ContractCallerRaw struct {
	Contract *ContractCaller // Generic read-only contract binding to access the raw methods on
}

// ContractTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ContractTransactorRaw struct {
	Contract *ContractTransactor // Generic write-only contract binding to access the raw methods on
}

// NewContract creates a new instance of Contract, bound to a specific deployed contract.
func NewContract(address common.Address, backend bind.ContractBackend) (*Contract, error) {
	contract, err := bindContract(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Contract{ContractCaller: ContractCaller{contract: contract}, ContractTransactor: ContractTransactor{contract: contract}, ContractFilterer: ContractFilterer{contract: contract}}, nil
}

// NewContractCaller creates a new read-only instance of Contract, bound to a specific deployed contract.
func NewContractCaller(address common.Address, caller bind.ContractCaller) (*ContractCaller, error) {
	contract, err := bindContract(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ContractCaller{contract: contract}, nil
}

// NewContractTransactor creates a new write-only instance of Contract, bound to a specific deployed contract.
func NewContractTransactor(address common.Address, transactor bind.ContractTransactor) (*ContractTransactor, error) {
	contract, err := bindContract(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ContractTransactor{contract: contract}, nil
}

// NewContractFilterer creates a new log filterer instance of Contract, bound to a specific deployed contract.
func NewContractFilterer(address common.Address, filterer bind.ContractFilterer) (*ContractFilterer, error) {
	contract, err := bindContract(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ContractFilterer{contract: contract}, nil
}

// bindContract binds a generic wrapper to an already deployed contract.
func bindContract(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := ContractMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Contract *ContractRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Contract.Contract.ContractCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Contract *ContractRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.Contract.ContractTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Contract *ContractRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Contract.Contract.ContractTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Contract *ContractCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Contract.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Contract *ContractTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Contract *ContractTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Contract.Contract.contract.Transact(opts, method, params...)
}

// GetRKResult is a free data retrieval call binding the contract method 0x69222312.
//
// Solidity: function GetRKResult() view returns(bool)
func (_Contract *ContractCaller) GetRKResult(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "GetRKResult")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// GetRKResult is a free data retrieval call binding the contract method 0x69222312.
//
// Solidity: function GetRKResult() view returns(bool)
func (_Contract *ContractSession) GetRKResult() (bool, error) {
	return _Contract.Contract.GetRKResult(&_Contract.CallOpts)
}

// GetRKResult is a free data retrieval call binding the contract method 0x69222312.
//
// Solidity: function GetRKResult() view returns(bool)
func (_Contract *ContractCallerSession) GetRKResult() (bool, error) {
	return _Contract.Contract.GetRKResult(&_Contract.CallOpts)
}

// GetSKResult is a free data retrieval call binding the contract method 0x0be2ef69.
//
// Solidity: function GetSKResult() view returns(bool)
func (_Contract *ContractCaller) GetSKResult(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "GetSKResult")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// GetSKResult is a free data retrieval call binding the contract method 0x0be2ef69.
//
// Solidity: function GetSKResult() view returns(bool)
func (_Contract *ContractSession) GetSKResult() (bool, error) {
	return _Contract.Contract.GetSKResult(&_Contract.CallOpts)
}

// GetSKResult is a free data retrieval call binding the contract method 0x0be2ef69.
//
// Solidity: function GetSKResult() view returns(bool)
func (_Contract *ContractCallerSession) GetSKResult() (bool, error) {
	return _Contract.Contract.GetSKResult(&_Contract.CallOpts)
}

// AccessTree is a free data retrieval call binding the contract method 0xef6bc912.
//
// Solidity: function accessTree(uint256 ) view returns(bool isLeaf, uint256 threshold, bytes32 attribute)
func (_Contract *ContractCaller) AccessTree(opts *bind.CallOpts, arg0 *big.Int) (struct {
	IsLeaf    bool
	Threshold *big.Int
	Attribute [32]byte
}, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "accessTree", arg0)

	outstruct := new(struct {
		IsLeaf    bool
		Threshold *big.Int
		Attribute [32]byte
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.IsLeaf = *abi.ConvertType(out[0], new(bool)).(*bool)
	outstruct.Threshold = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.Attribute = *abi.ConvertType(out[2], new([32]byte)).(*[32]byte)

	return *outstruct, err

}

// AccessTree is a free data retrieval call binding the contract method 0xef6bc912.
//
// Solidity: function accessTree(uint256 ) view returns(bool isLeaf, uint256 threshold, bytes32 attribute)
func (_Contract *ContractSession) AccessTree(arg0 *big.Int) (struct {
	IsLeaf    bool
	Threshold *big.Int
	Attribute [32]byte
}, error) {
	return _Contract.Contract.AccessTree(&_Contract.CallOpts, arg0)
}

// AccessTree is a free data retrieval call binding the contract method 0xef6bc912.
//
// Solidity: function accessTree(uint256 ) view returns(bool isLeaf, uint256 threshold, bytes32 attribute)
func (_Contract *ContractCallerSession) AccessTree(arg0 *big.Int) (struct {
	IsLeaf    bool
	Threshold *big.Int
	Attribute [32]byte
}, error) {
	return _Contract.Contract.AccessTree(&_Contract.CallOpts, arg0)
}

// GetNode is a free data retrieval call binding the contract method 0x4f0f4aa9.
//
// Solidity: function getNode(uint256 _nodeId) view returns(bool, uint256, bytes32, uint256[])
func (_Contract *ContractCaller) GetNode(opts *bind.CallOpts, _nodeId *big.Int) (bool, *big.Int, [32]byte, []*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "getNode", _nodeId)

	if err != nil {
		return *new(bool), *new(*big.Int), *new([32]byte), *new([]*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)
	out1 := *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	out2 := *abi.ConvertType(out[2], new([32]byte)).(*[32]byte)
	out3 := *abi.ConvertType(out[3], new([]*big.Int)).(*[]*big.Int)

	return out0, out1, out2, out3, err

}

// GetNode is a free data retrieval call binding the contract method 0x4f0f4aa9.
//
// Solidity: function getNode(uint256 _nodeId) view returns(bool, uint256, bytes32, uint256[])
func (_Contract *ContractSession) GetNode(_nodeId *big.Int) (bool, *big.Int, [32]byte, []*big.Int, error) {
	return _Contract.Contract.GetNode(&_Contract.CallOpts, _nodeId)
}

// GetNode is a free data retrieval call binding the contract method 0x4f0f4aa9.
//
// Solidity: function getNode(uint256 _nodeId) view returns(bool, uint256, bytes32, uint256[])
func (_Contract *ContractCallerSession) GetNode(_nodeId *big.Int) (bool, *big.Int, [32]byte, []*big.Int, error) {
	return _Contract.Contract.GetNode(&_Contract.CallOpts, _nodeId)
}

// GetRootNode is a free data retrieval call binding the contract method 0x38d1fcc3.
//
// Solidity: function getRootNode() view returns(bool, uint256, bytes32, uint256[])
func (_Contract *ContractCaller) GetRootNode(opts *bind.CallOpts) (bool, *big.Int, [32]byte, []*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "getRootNode")

	if err != nil {
		return *new(bool), *new(*big.Int), *new([32]byte), *new([]*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)
	out1 := *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	out2 := *abi.ConvertType(out[2], new([32]byte)).(*[32]byte)
	out3 := *abi.ConvertType(out[3], new([]*big.Int)).(*[]*big.Int)

	return out0, out1, out2, out3, err

}

// GetRootNode is a free data retrieval call binding the contract method 0x38d1fcc3.
//
// Solidity: function getRootNode() view returns(bool, uint256, bytes32, uint256[])
func (_Contract *ContractSession) GetRootNode() (bool, *big.Int, [32]byte, []*big.Int, error) {
	return _Contract.Contract.GetRootNode(&_Contract.CallOpts)
}

// GetRootNode is a free data retrieval call binding the contract method 0x38d1fcc3.
//
// Solidity: function getRootNode() view returns(bool, uint256, bytes32, uint256[])
func (_Contract *ContractCallerSession) GetRootNode() (bool, *big.Int, [32]byte, []*big.Int, error) {
	return _Contract.Contract.GetRootNode(&_Contract.CallOpts)
}

// RootNodeId is a free data retrieval call binding the contract method 0x5ba5342a.
//
// Solidity: function rootNodeId() view returns(uint256)
func (_Contract *ContractCaller) RootNodeId(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "rootNodeId")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// RootNodeId is a free data retrieval call binding the contract method 0x5ba5342a.
//
// Solidity: function rootNodeId() view returns(uint256)
func (_Contract *ContractSession) RootNodeId() (*big.Int, error) {
	return _Contract.Contract.RootNodeId(&_Contract.CallOpts)
}

// RootNodeId is a free data retrieval call binding the contract method 0x5ba5342a.
//
// Solidity: function rootNodeId() view returns(uint256)
func (_Contract *ContractCallerSession) RootNodeId() (*big.Int, error) {
	return _Contract.Contract.RootNodeId(&_Contract.CallOpts)
}

// ReKeyVer is a paid mutator transaction binding the contract method 0x63ca7a56.
//
// Solidity: function ReKeyVer((uint256,uint256) d1, (uint256,uint256) d2) returns()
func (_Contract *ContractTransactor) ReKeyVer(opts *bind.TransactOpts, d1 TradeG1Point, d2 TradeG1Point) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "ReKeyVer", d1, d2)
}

// ReKeyVer is a paid mutator transaction binding the contract method 0x63ca7a56.
//
// Solidity: function ReKeyVer((uint256,uint256) d1, (uint256,uint256) d2) returns()
func (_Contract *ContractSession) ReKeyVer(d1 TradeG1Point, d2 TradeG1Point) (*types.Transaction, error) {
	return _Contract.Contract.ReKeyVer(&_Contract.TransactOpts, d1, d2)
}

// ReKeyVer is a paid mutator transaction binding the contract method 0x63ca7a56.
//
// Solidity: function ReKeyVer((uint256,uint256) d1, (uint256,uint256) d2) returns()
func (_Contract *ContractTransactorSession) ReKeyVer(d1 TradeG1Point, d2 TradeG1Point) (*types.Transaction, error) {
	return _Contract.Contract.ReKeyVer(&_Contract.TransactOpts, d1, d2)
}

// SubKeyVer is a paid mutator transaction binding the contract method 0x30edd108.
//
// Solidity: function SubKeyVer((uint256,uint256) sk1, (uint256,uint256) sk2) returns()
func (_Contract *ContractTransactor) SubKeyVer(opts *bind.TransactOpts, sk1 TradeG1Point, sk2 TradeG1Point) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "SubKeyVer", sk1, sk2)
}

// SubKeyVer is a paid mutator transaction binding the contract method 0x30edd108.
//
// Solidity: function SubKeyVer((uint256,uint256) sk1, (uint256,uint256) sk2) returns()
func (_Contract *ContractSession) SubKeyVer(sk1 TradeG1Point, sk2 TradeG1Point) (*types.Transaction, error) {
	return _Contract.Contract.SubKeyVer(&_Contract.TransactOpts, sk1, sk2)
}

// SubKeyVer is a paid mutator transaction binding the contract method 0x30edd108.
//
// Solidity: function SubKeyVer((uint256,uint256) sk1, (uint256,uint256) sk2) returns()
func (_Contract *ContractTransactorSession) SubKeyVer(sk1 TradeG1Point, sk2 TradeG1Point) (*types.Transaction, error) {
	return _Contract.Contract.SubKeyVer(&_Contract.TransactOpts, sk1, sk2)
}

// UploadABECipher is a paid mutator transaction binding the contract method 0x918377e2.
//
// Solidity: function UploadABECipher((uint256,uint256) com, (uint256,bool,uint256,uint256,bytes32,uint256[])[] abeNodes, (uint256,uint256) abeCom, (uint256,uint256) abeC, (uint256[2],uint256[2]) abe_C, bytes32[] abeAttr, (uint256,uint256)[] abeC1, (uint256,uint256)[] abeC2, (uint256,uint256)[] abeC3) returns()
func (_Contract *ContractTransactor) UploadABECipher(opts *bind.TransactOpts, com TradeG1Point, abeNodes []TradeNodeInput, abeCom TradeG1Point, abeC TradeG1Point, abe_C TradeG2Point, abeAttr [][32]byte, abeC1 []TradeG1Point, abeC2 []TradeG1Point, abeC3 []TradeG1Point) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "UploadABECipher", com, abeNodes, abeCom, abeC, abe_C, abeAttr, abeC1, abeC2, abeC3)
}

// UploadABECipher is a paid mutator transaction binding the contract method 0x918377e2.
//
// Solidity: function UploadABECipher((uint256,uint256) com, (uint256,bool,uint256,uint256,bytes32,uint256[])[] abeNodes, (uint256,uint256) abeCom, (uint256,uint256) abeC, (uint256[2],uint256[2]) abe_C, bytes32[] abeAttr, (uint256,uint256)[] abeC1, (uint256,uint256)[] abeC2, (uint256,uint256)[] abeC3) returns()
func (_Contract *ContractSession) UploadABECipher(com TradeG1Point, abeNodes []TradeNodeInput, abeCom TradeG1Point, abeC TradeG1Point, abe_C TradeG2Point, abeAttr [][32]byte, abeC1 []TradeG1Point, abeC2 []TradeG1Point, abeC3 []TradeG1Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadABECipher(&_Contract.TransactOpts, com, abeNodes, abeCom, abeC, abe_C, abeAttr, abeC1, abeC2, abeC3)
}

// UploadABECipher is a paid mutator transaction binding the contract method 0x918377e2.
//
// Solidity: function UploadABECipher((uint256,uint256) com, (uint256,bool,uint256,uint256,bytes32,uint256[])[] abeNodes, (uint256,uint256) abeCom, (uint256,uint256) abeC, (uint256[2],uint256[2]) abe_C, bytes32[] abeAttr, (uint256,uint256)[] abeC1, (uint256,uint256)[] abeC2, (uint256,uint256)[] abeC3) returns()
func (_Contract *ContractTransactorSession) UploadABECipher(com TradeG1Point, abeNodes []TradeNodeInput, abeCom TradeG1Point, abeC TradeG1Point, abe_C TradeG2Point, abeAttr [][32]byte, abeC1 []TradeG1Point, abeC2 []TradeG1Point, abeC3 []TradeG1Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadABECipher(&_Contract.TransactOpts, com, abeNodes, abeCom, abeC, abe_C, abeAttr, abeC1, abeC2, abeC3)
}

// UploadMPK is a paid mutator transaction binding the contract method 0x19ae829a.
//
// Solidity: function UploadMPK((uint256,uint256) g1, (uint256[2],uint256[2]) g2, (uint256,uint256) u1, (uint256[2],uint256[2]) u2, (uint256,uint256) h1, (uint256[2],uint256[2]) h2, (uint256,uint256) alphaG1, bytes32[] attrHxs, (uint256,uint256)[] hxsG1, (uint256[2],uint256[2])[] hxsG2) returns()
func (_Contract *ContractTransactor) UploadMPK(opts *bind.TransactOpts, g1 TradeG1Point, g2 TradeG2Point, u1 TradeG1Point, u2 TradeG2Point, h1 TradeG1Point, h2 TradeG2Point, alphaG1 TradeG1Point, attrHxs [][32]byte, hxsG1 []TradeG1Point, hxsG2 []TradeG2Point) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "UploadMPK", g1, g2, u1, u2, h1, h2, alphaG1, attrHxs, hxsG1, hxsG2)
}

// UploadMPK is a paid mutator transaction binding the contract method 0x19ae829a.
//
// Solidity: function UploadMPK((uint256,uint256) g1, (uint256[2],uint256[2]) g2, (uint256,uint256) u1, (uint256[2],uint256[2]) u2, (uint256,uint256) h1, (uint256[2],uint256[2]) h2, (uint256,uint256) alphaG1, bytes32[] attrHxs, (uint256,uint256)[] hxsG1, (uint256[2],uint256[2])[] hxsG2) returns()
func (_Contract *ContractSession) UploadMPK(g1 TradeG1Point, g2 TradeG2Point, u1 TradeG1Point, u2 TradeG2Point, h1 TradeG1Point, h2 TradeG2Point, alphaG1 TradeG1Point, attrHxs [][32]byte, hxsG1 []TradeG1Point, hxsG2 []TradeG2Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadMPK(&_Contract.TransactOpts, g1, g2, u1, u2, h1, h2, alphaG1, attrHxs, hxsG1, hxsG2)
}

// UploadMPK is a paid mutator transaction binding the contract method 0x19ae829a.
//
// Solidity: function UploadMPK((uint256,uint256) g1, (uint256[2],uint256[2]) g2, (uint256,uint256) u1, (uint256[2],uint256[2]) u2, (uint256,uint256) h1, (uint256[2],uint256[2]) h2, (uint256,uint256) alphaG1, bytes32[] attrHxs, (uint256,uint256)[] hxsG1, (uint256[2],uint256[2])[] hxsG2) returns()
func (_Contract *ContractTransactorSession) UploadMPK(g1 TradeG1Point, g2 TradeG2Point, u1 TradeG1Point, u2 TradeG2Point, h1 TradeG1Point, h2 TradeG2Point, alphaG1 TradeG1Point, attrHxs [][32]byte, hxsG1 []TradeG1Point, hxsG2 []TradeG2Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadMPK(&_Contract.TransactOpts, g1, g2, u1, u2, h1, h2, alphaG1, attrHxs, hxsG1, hxsG2)
}

// UploadPK is a paid mutator transaction binding the contract method 0x99637082.
//
// Solidity: function UploadPK((uint256,uint256) pko, (uint256[2],uint256[2]) vko, (uint256,uint256) pku, (uint256[2],uint256[2]) vku) returns()
func (_Contract *ContractTransactor) UploadPK(opts *bind.TransactOpts, pko TradeG1Point, vko TradeG2Point, pku TradeG1Point, vku TradeG2Point) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "UploadPK", pko, vko, pku, vku)
}

// UploadPK is a paid mutator transaction binding the contract method 0x99637082.
//
// Solidity: function UploadPK((uint256,uint256) pko, (uint256[2],uint256[2]) vko, (uint256,uint256) pku, (uint256[2],uint256[2]) vku) returns()
func (_Contract *ContractSession) UploadPK(pko TradeG1Point, vko TradeG2Point, pku TradeG1Point, vku TradeG2Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadPK(&_Contract.TransactOpts, pko, vko, pku, vku)
}

// UploadPK is a paid mutator transaction binding the contract method 0x99637082.
//
// Solidity: function UploadPK((uint256,uint256) pko, (uint256[2],uint256[2]) vko, (uint256,uint256) pku, (uint256[2],uint256[2]) vku) returns()
func (_Contract *ContractTransactorSession) UploadPK(pko TradeG1Point, vko TradeG2Point, pku TradeG1Point, vku TradeG2Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadPK(&_Contract.TransactOpts, pko, vko, pku, vku)
}

// UploadPayCipher is a paid mutator transaction binding the contract method 0x1f422ed7.
//
// Solidity: function UploadPayCipher((uint256,uint256) c2, (uint256,uint256) c2Com, (uint256,uint256) c3Com, (uint256,uint256) subC1, (uint256[2],uint256[2]) subC2) returns()
func (_Contract *ContractTransactor) UploadPayCipher(opts *bind.TransactOpts, c2 TradeG1Point, c2Com TradeG1Point, c3Com TradeG1Point, subC1 TradeG1Point, subC2 TradeG2Point) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "UploadPayCipher", c2, c2Com, c3Com, subC1, subC2)
}

// UploadPayCipher is a paid mutator transaction binding the contract method 0x1f422ed7.
//
// Solidity: function UploadPayCipher((uint256,uint256) c2, (uint256,uint256) c2Com, (uint256,uint256) c3Com, (uint256,uint256) subC1, (uint256[2],uint256[2]) subC2) returns()
func (_Contract *ContractSession) UploadPayCipher(c2 TradeG1Point, c2Com TradeG1Point, c3Com TradeG1Point, subC1 TradeG1Point, subC2 TradeG2Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadPayCipher(&_Contract.TransactOpts, c2, c2Com, c3Com, subC1, subC2)
}

// UploadPayCipher is a paid mutator transaction binding the contract method 0x1f422ed7.
//
// Solidity: function UploadPayCipher((uint256,uint256) c2, (uint256,uint256) c2Com, (uint256,uint256) c3Com, (uint256,uint256) subC1, (uint256[2],uint256[2]) subC2) returns()
func (_Contract *ContractTransactorSession) UploadPayCipher(c2 TradeG1Point, c2Com TradeG1Point, c3Com TradeG1Point, subC1 TradeG1Point, subC2 TradeG2Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadPayCipher(&_Contract.TransactOpts, c2, c2Com, c3Com, subC1, subC2)
}

// UploadSPK is a paid mutator transaction binding the contract method 0x783660c9.
//
// Solidity: function UploadSPK((uint256,uint256) gammaG1) returns()
func (_Contract *ContractTransactor) UploadSPK(opts *bind.TransactOpts, gammaG1 TradeG1Point) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "UploadSPK", gammaG1)
}

// UploadSPK is a paid mutator transaction binding the contract method 0x783660c9.
//
// Solidity: function UploadSPK((uint256,uint256) gammaG1) returns()
func (_Contract *ContractSession) UploadSPK(gammaG1 TradeG1Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadSPK(&_Contract.TransactOpts, gammaG1)
}

// UploadSPK is a paid mutator transaction binding the contract method 0x783660c9.
//
// Solidity: function UploadSPK((uint256,uint256) gammaG1) returns()
func (_Contract *ContractTransactorSession) UploadSPK(gammaG1 TradeG1Point) (*types.Transaction, error) {
	return _Contract.Contract.UploadSPK(&_Contract.TransactOpts, gammaG1)
}

// Inv is a paid mutator transaction binding the contract method 0x338255f3.
//
// Solidity: function inv(uint256 a, uint256 prime) returns(uint256)
func (_Contract *ContractTransactor) Inv(opts *bind.TransactOpts, a *big.Int, prime *big.Int) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "inv", a, prime)
}

// Inv is a paid mutator transaction binding the contract method 0x338255f3.
//
// Solidity: function inv(uint256 a, uint256 prime) returns(uint256)
func (_Contract *ContractSession) Inv(a *big.Int, prime *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.Inv(&_Contract.TransactOpts, a, prime)
}

// Inv is a paid mutator transaction binding the contract method 0x338255f3.
//
// Solidity: function inv(uint256 a, uint256 prime) returns(uint256)
func (_Contract *ContractTransactorSession) Inv(a *big.Int, prime *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.Inv(&_Contract.TransactOpts, a, prime)
}

// UploadAccessTree is a paid mutator transaction binding the contract method 0xc4fcb357.
//
// Solidity: function uploadAccessTree((uint256,bool,uint256,uint256,bytes32,uint256[])[] _nodes) returns()
func (_Contract *ContractTransactor) UploadAccessTree(opts *bind.TransactOpts, _nodes []TradeNodeInput) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "uploadAccessTree", _nodes)
}

// UploadAccessTree is a paid mutator transaction binding the contract method 0xc4fcb357.
//
// Solidity: function uploadAccessTree((uint256,bool,uint256,uint256,bytes32,uint256[])[] _nodes) returns()
func (_Contract *ContractSession) UploadAccessTree(_nodes []TradeNodeInput) (*types.Transaction, error) {
	return _Contract.Contract.UploadAccessTree(&_Contract.TransactOpts, _nodes)
}

// UploadAccessTree is a paid mutator transaction binding the contract method 0xc4fcb357.
//
// Solidity: function uploadAccessTree((uint256,bool,uint256,uint256,bytes32,uint256[])[] _nodes) returns()
func (_Contract *ContractTransactorSession) UploadAccessTree(_nodes []TradeNodeInput) (*types.Transaction, error) {
	return _Contract.Contract.UploadAccessTree(&_Contract.TransactOpts, _nodes)
}
