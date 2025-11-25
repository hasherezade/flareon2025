from z3 import *

# digit_constants[d][pos] : dumped 10x25 table
digit_constants = [
    #Digit: 0
    [
    0x19b3240445aa06, 0x6f63394844df78, 0x6df6a4586e71c0, 0x4ea15fc542c9c0, 0x3ac57453ace252, 
    0x6402164c9fdb19, 0x69b5253875b96, 0x9c0d47eac35d2d, 0x30b9da3c1bfe7, 0x3a03c1d1d02f29, 
    0x1d392355df459c, 0x8484a22a795e4, 0xbe331dd3107ad, 0x19c7c11da4e4a2, 0x1796e76685e997, 
    0x9bdc1f78073127, 0xcce53b2df56140, 0x1dc6931c286db2, 0x139d946e9d6d82, 0x72a31cfde71ef6, 
    0x40a5db3578d586, 0xc427156a9e2860, 0x537869c92a42d0, 0x8cc856e432bc50, 0x20ccd008ad41a
    ],
    #Digit: 1
    [
    0xf2eb6684284ac, 0x3ed168087f3548, 0x49de34ffc63ec0, 0x1ca2f34f18cd40, 0x6229b366fe169, 
    0x483f192b06217f, 0x2be31f155ab714, 0x6fd7cb84fd4ad7, 0x16f0557c6f1b97, 0x255e081f63ba07, 
    0xbc35faa41240, 0x5eb45f3e513ac, 0x5e391dd240e89d, 0x7fa2b9a827fae, 0x5dc0c3e3261cdf, 
    0x75583891352145, 0x926ec5880f9992, 0xed19ad19480be, 0xb0e0c55a4d6238, 0x46a5661935d9ca, 
    0x22f572e6839826, 0x88b763cb6fb9f0, 0x1da1d095b7c0b4, 0x62360169143a78, 0x3684bcd9a0f789
    ],
    #Digit: 2
    [
    0xc38d14df6d665, 0x6391d7049dde8, 0x39fee368e99380, 0xa614b2dc1c6980, 0xacb3ff351198ab, 
    0x1e5cb35f54fa69, 0x21ae09901bf552, 0x6255b824338303, 0x105a5256455ed6, 0x1b8260c83dd73c, 
    0x4d5ba7b7c6db28, 0x46247570894a4, 0x39874c7ffb294c, 0x42193cc5270058, 0x3a76362613dd95, 
    0x4f18252739a5ac, 0x81fa523e38b793, 0x3a82193f6ef346, 0x97d9725be8876e, 0xbd4c34161b102, 
    0x1133b875bed53a, 0x2f08d6e954e096, 0xbf7b1f10223116, 0x55333012d9dd23, 0x2525f943737b70
    ],
    #Digit: 3
    [
    0x1d3a557cd3a980, 0x8114813c91a610, 0x7a11de14c79e80, 0x60d84a48824900, 0x4c6c9cdbce1fe5, 
    0x6e1e405c548974, 0xb221597f1d3d8, 0xac26e207a0a6c5, 0x575f94a1e493b, 0x4188e0049c9eba, 
    0x26c6dd80773e62, 0x924ce94df0690, 0x15e2ab5e23c478, 0x2043847b9eedd8, 0x201bb9ea8ed81c, 
    0xc857c28be5198, 0x481af6ccb653b, 0x23394341031ac0, 0x26b598f9022c30, 0x82a99a5de4c84f, 
    0x4a9b4a38cf1460, 0xd9ccf65d9cd7a4, 0x6586f47fc6cf52, 0x9c4964e3f15005, 0x86bb1a4a4aa7d
    ],
    #Digit: 4
    [
    0x26d8e6dc23319d, 0xa8fa7b20f1e228, 0xd8dc90e996e40, 0x9280b83fadd240, 0x7c9128173ea742, 
    0x137e71b08ca2aa, 0x1556ddaa385c92, 0x23700dd18b0e3c, 0xc0c1389db1c28, 0x527eec073c111b, 
    0x3c52c884071124, 0x1d5530ea52210, 0x312496ae1c4433, 0x2ee265cbaea1ae, 0x33509b969e3741, 
    0x32c55970ea1358, 0x39fc6f33cb770b, 0x2f828795a6e6be, 0x51c2fa15841d7e, 0xae5a988393338f, 
    0x65c33e4f5a2fc0, 0x17c3e165050bf0, 0x8e40676e4927e0, 0x18a07ddc589b2c, 0x19ca34adee1b3a
    ],
    #Digit: 5
    [
    0x1c544f24d1b429, 0x786666be83b978, 0x7146bfc66e2740, 0x60801a9a7374c0, 0x47ed36357ff53c, 
    0x6928a14a143271, 0x7d821185844ec, 0xabd8d1a448644c, 0x4d8773736490a, 0x3dd8df72e747e1, 
    0x1fd5838c6c7f50, 0x920a24b9448d0, 0x1356d94e3c824f, 0x1d1555557808f2, 0x19eb1c9c94e6a8, 
    0xc421f0a303c70, 0xdb8605e2f4aa0e, 0x208d625a5fd472, 0x18d5fbe4cda4c8, 0x825e0ae4d3d5f5, 
    0x481234127842a2, 0xcf2b002b1ad140, 0x58692f2e100a24, 0x9bfe0fedbf05dc, 0x6cc51df5a1f44
    ],
    #Digit: 6
    [
    0x17f846e0621293, 0x6ae188a0bc46f0, 0x680673db489e00, 0x49fe057966cc00, 0x321b2c8decc760, 
    0x616eb297eddb28, 0x462d157005089, 0x97f36052caa668, 0x1dc3a46d3eb22, 0x38195731a5d0ae, 
    0x188898b9e96d66, 0x81027f2a79420, 0x6fb9313a4228e, 0x1820c6ca831f20, 0x1368e07f2e794f, 
    0x984973478dc5ac, 0xc34699db257145, 0x1c635aa6df8398, 0xa3f26df601552, 0x6e8ea108204593, 
    0x3bc3c87f8c0454, 0xbea37cef15e1fa, 0x4a9ca491835636, 0x88d54339cf6cf1, 0x4661d5224e5470
    ],
    #Digit: 7
    [
    0x1b6e4030f71f3d, 0x6fb9a153c78328, 0x6e31309b7b8940, 0x579189abc15440, 0x436e1cad683194, 
    0x6431716b60df88, 0x6b104399cedbc, 0xa3f30cb6971d36, 0x43afa29a5046e, 0x3a28381b02c813, 
    0x1d66839ef1a1c0, 0x8b4887801a9fc, 0x10cafc6dd92ae3, 0x19e699125f8740, 0x17bfd098c23630, 
    0x56017c15fbdd1, 0xd6872c5cc11542, 0x1de0f95cf827ae, 0x13f8dff2fe8408, 0x7a7fe273c35a4c, 
    0x4588ce32dcf25a, 0xc48cee7bae850c, 0x53cfddbdd2f61c, 0x9463624aaca2c6, 0x52ced44ed58cc
    ],
    #Digit: 8
    [
    0x80f42a7139e80, 0x1b18d762cb44c8, 0x316c3afcb92ac0, 0xb2f907a133b2c0, 0x97de278c5e1226, 
    0x2a4a823d6d822d, 0x1e79b0a36cdaff, 0x4f56bf7afe673b, 0x12101a50f4e1fb, 0x162f7a6e9d784f, 
    0x58a12d4900a2fa, 0x35e3da634fb94, 0x409bc32bba4e37, 0x3d81e379f6b82a, 0x448303cfd4dd31, 
    0x5906717cf6c571, 0x6ad52b4c617cf3, 0x3d2149d449636, 0x8a5498f0183bb0, 0x172c91b106b2ed, 
    0x573d341f00d72, 0x489420271c9606, 0xb2b5098a832538, 0x42e7af41e9bd7c, 0x29a7cada9c4cb1
    ],
    #Digit: 9
    [
    0x1fcac56f82739c, 0x921c4279b1a9a8, 0x82deefe21a73c0, 0x612f00f6ea6080, 0x489730c9aa7e6a, 
    0x6e4f38a8434132, 0xa266dd02d7453, 0x708e71fcee988, 0x737572378fc07, 0x48c67301dafecb, 
    0x2db81c4ae88d20, 0x928d4d1040ed8, 0x13b66fde55b77c, 0x2062f49da45ab4, 0x1e41e65b7afc35, 
    0x1a062a307bcabd, 0x12c1ca7eae79a6, 0x28782f9453efde, 0x3496095ef45282, 0x82f69b85b1a2a1, 
    0x48724d79b38078, 0xda31dc2c7fdbce, 0x619c35508aeaba, 0xab36b7c0777858, 0xd0cb5244ca7fd
    ]
]


NUM_POS   = 25
NUM_DIGIT = 10

target = 0xBC42D5779FEC401

s = Solver()

# unknown digits d[0..24]
digits = [Int(f"d{i}") for i in range(NUM_POS)]
for d in digits:
    s.add(d >= 0, d < NUM_DIGIT)

# contrib[pos] = digit_constants[digits[pos]][pos]
contribs = []
for pos in range(NUM_POS):
    term = IntVal(0)
    for dig in range(NUM_DIGIT):
        term = If(digits[pos] == dig,
                  IntVal(digit_constants[dig][pos]),
                  term)
    contribs.append(term)

total = Sum(contribs)
s.add(total == target)

print("Solving...")
if s.check() == sat:
    m = s.model()
    sol = [m[d].as_long() for d in digits]
    print("Code:", "".join(str(x) for x in sol))
else:
    print("No solution")
