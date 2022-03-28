package xsha256

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func Test_Addmod32(t *testing.T) {
	if AddMod32(1, 2) != 4 {
		t.Error("AddMod32 case 1 error")
	}
	if AddMod32(4294967295, 1) != 0 {
		t.Error("AddMod32 case 2 error")
	}
	if AddMod32(3050487260, 3710144918) != 2465664882 {
		t.Error("AddMod32 case 3 error")
	}
}

func Test_RotR32(t *testing.T) {
	if RotR32(2, 1) != 1 {
		t.Error("RotR32 case 1 error")
	}
	if RotR32(1, 1) != 2147483648 {
		t.Error("RotR32 case 2 error")
	}
	if RotR32(2919882184, 31) != 1544797073 {
		t.Error("RotR32 case 3 error")
	}
}

func Test_Little_Sigma0(t *testing.T) {
	if Little_Sigma0(1114723206) != 1345017931 {
		t.Error("Little_Sigma0 case 1 error")
	}
}

func Test_Little_Sigma1(t *testing.T) {
	if Little_Sigma1(1232674167) != 2902922196 {
		t.Error("Little_Sigma1 case 1 error")
	}
}

func Test_BytesToWords(t *testing.T) {
	words := BytesToWords([]byte("iguana wombat dog kangaroo llama turkey yak unicorn sheep xenoce"))
	if !reflect.DeepEqual(words,
		[]uint32{1768387937, 1851859063, 1869439585, 1948279919, 1730177889, 1852268914, 1869553772, 1818324321,
			544503154, 1801812256, 2036427552, 1970170211, 1869770272, 1936221541, 1881176165, 1852793701,
			3002878561, 3711121932, 1520676164, 3002441970, 2935068969, 1610329529, 1904580351, 3219988740,
			2337695268, 263015313, 2120931855, 131203777, 3818546915, 19163115, 3479924161, 2154860703,
			1790169326, 516580487, 2414737634, 909025701, 2241053595, 1237268359, 3797503938, 1773623028,
			2840671725, 2299292186, 1933596460, 2279513616, 514132674, 3245155609, 1753922983, 2241450350,
			2449659630, 262239956, 773552098, 3253131632, 3863807927, 879696536, 3143654396, 3973063648,
			509015903, 270850193, 1893431553, 719566283, 2310657204, 365781698, 3761063438, 1007484868}) {
		t.Error("BytesToWords case 1 error")
	}
}

func Test_Big_Sigma0(t *testing.T) {
	if Big_Sigma0(3536071395) != 3003388882 {
		t.Error("Big_Sigma0 case 1 error")
	}
}

func Test_Big_Sigma1(t *testing.T) {
	if Big_Sigma1(651015076) != 2194029931 {
		t.Error("Big_Sigma1 case 1 error")
	}
}

func Test_Choice(t *testing.T) {
	if Choice(2749825547, 776049372, 1213590135) != 1783753340 {
		t.Error("Choice case 1 error")
	}
}

func Test_Majority(t *testing.T) {
	if Majority(3758166654, 2821345890, 1850678816) != 3893039714 {
		t.Error("Majority case 1 error")
	}
}

func Test_Round(t *testing.T) {
	state := State{list: [8]uint32{2739944672, 3126690193, 4191866847, 1163785745,
		3714074692, 1172792371, 283469062, 826169706}}
	Round(&state, 961987163, 3221900128)

	if !reflect.DeepEqual(state.list, [8]uint32{1724514418, 2739944672, 3126690193, 4191866847,
		1638715774, 3714074692, 1172792371, 283469062}) {
		t.Error("Round case 1 error")
	}
}

func Test_Compress(t *testing.T) {
	state := State{list: [8]uint32{2918946378, 1679978889, 1678006433, 650957219,
		379281712, 2112907926, 1775216060, 2152648190}}
	msg := []byte("manatee fox unicorn octopus dog fox fox llama vulture jaguar xen")
	Compress(&state, msg)

	if !reflect.DeepEqual(state.list, [8]uint32{1251501988, 1663226031, 2877128394, 4050467288,
		2375501075, 1434687977, 2625842981, 650253644}) {
		t.Error("Compress case 1 error")
	}
}

func Test_Padding(t *testing.T) {
	pad := Padding(0)
	if hex.EncodeToString(pad) != "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" {
		t.Error("Padding case 1 error")
	}
	pad = Padding(1)
	if hex.EncodeToString(pad) != "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008" {
		t.Error("Padding case 2 error")
	}
	pad = Padding(55)
	if hex.EncodeToString(pad) != "8000000000000001b8" {
		t.Error("Padding case 3 error")
	}
	pad = Padding(56)
	if hex.EncodeToString(pad) != "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0" {
		t.Error("Padding case 4 error")
	}
	pad = Padding(64)
	if hex.EncodeToString(pad) != "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200" {
		t.Error("Padding case 5 error")
	}
	pad = Padding(492022654431536432)
	if hex.EncodeToString(pad) != "800000000000000036a01ffa96b12980" {
		t.Error("Padding case 6 error")
	}
}

func Test_Hash(t *testing.T) {
	hash := Hash([]byte(""))
	if string(hash) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Error("Padding case 1 error")
	}
	hash = Hash([]byte("hello world"))
	if string(hash) != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Error("Padding case 2 error")
	}
	hash = Hash([]byte("aardvark zebra yak pig jaguar aardvark rhinoceros butte"))
	if string(hash) != "4b45e1bec21185865d1628a8a502eed789193a3c253a529983e4bc17fa65f32b" {
		t.Error("Padding case 3 error")
	}
	hash = Hash([]byte("narwhal dog llama llama giraffe narwhal octopus dog xeno"))
	if string(hash) != "99069f1eba4c874aba649c17136a253e1dd504cda936ab77cf189c2cf9eb88ff" {
		t.Error("Padding case 4 error")
	}
	hash = Hash([]byte("John Jacob Jingleheimer Schmidt! His name is my name too. Whenever we go out the people always shout there goes John Jacob Jingleheimer Schmidt! Nanananananana..."))
	if string(hash) != "68b74d91364475247c10bfee2621eaa13bcabb033ed1dee58b74c05e7944489a" {
		t.Error("Padding case 5 error")
	}
}
