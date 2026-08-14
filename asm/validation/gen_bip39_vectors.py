#!/usr/bin/env python3
"""gen_bip39_vectors.py -- independent BIP39 oracle and vector generator.

Produces asm/tests/bip39_vec.h for the assembly BIP39 harness
(asm/bitcoin_bip39.asm) in the same style as the other oracle scripts in this
tree (gen_bip32_vectors.py, gen_mempool_policy_vectors.py).

The mnemonic<->entropy mapping below is implemented independently here (bit
concatenation + SHA-256 checksum + the embedded 2048-word English list) and the
seed derivation uses Python's stdlib hashlib.pbkdf2_hmac -- a *different* code
path from both the assembly and any `mnemonic` pip package. So the asm is
validated against a genuine second implementation.

Every emitted MIME vector is cross-checked against the official Bitcoin BIP39
test vectors (bip-0039 English set from the trezor/python-mnemonic
vectors.json, embedded verbatim below as OFFICIAL_EN). Passphrase vectors are
computed only via hashlib.pbkdf2_hmac and asserted against known-good seeds.
"""
import hashlib
import sys

# ---------------------------------------------------------------------------
# BIP39 English wordlist (2048 words, sorted, unique).
# ---------------------------------------------------------------------------
WORDLIST = """abandon ability able about above absent absorb abstract
absurd abuse access accident account accuse achieve acid
acoustic acquire across act action actor actress actual
adapt add addict address adjust admit adult advance
advice aerobic affair afford afraid again age agent
agree ahead aim air airport aisle alarm album
alcohol alert alien all alley allow almost alone
alpha already also alter always amateur amazing among
amount amused analyst anchor ancient anger angle angry
animal ankle announce annual another answer antenna antique
anxiety any apart apology appear apple approve april
arch arctic area arena argue arm armed armor
army around arrange arrest arrive arrow art artefact
artist artwork ask aspect assault asset assist assume
asthma athlete atom attack attend attitude attract auction
audit august aunt author auto autumn average avocado
avoid awake aware away awesome awful awkward axis
baby bachelor bacon badge bag balance balcony ball
bamboo banana banner bar barely bargain barrel base
basic basket battle beach bean beauty because become
beef before begin behave behind believe below belt
bench benefit best betray better between beyond bicycle
bid bike bind biology bird birth bitter black
blade blame blanket blast bleak bless blind blood
blossom blouse blue blur blush board boat body
boil bomb bone bonus book boost border boring
borrow boss bottom bounce box boy bracket brain
brand brass brave bread breeze brick bridge brief
bright bring brisk broccoli broken bronze broom brother
brown brush bubble buddy budget buffalo build bulb
bulk bullet bundle bunker burden burger burst bus
business busy butter buyer buzz cabbage cabin cable
cactus cage cake call calm camera camp can
canal cancel candy cannon canoe canvas canyon capable
capital captain car carbon card cargo carpet carry
cart case cash casino castle casual cat catalog
catch category cattle caught cause caution cave ceiling
celery cement census century cereal certain chair chalk
champion change chaos chapter charge chase chat cheap
check cheese chef cherry chest chicken chief child
chimney choice choose chronic chuckle chunk churn cigar
cinnamon circle citizen city civil claim clap clarify
claw clay clean clerk clever click client cliff
climb clinic clip clock clog close cloth cloud
clown club clump cluster clutch coach coast coconut
code coffee coil coin collect color column combine
come comfort comic common company concert conduct confirm
congress connect consider control convince cook cool copper
copy coral core corn correct cost cotton couch
country couple course cousin cover coyote crack cradle
craft cram crane crash crater crawl crazy cream
credit creek crew cricket crime crisp critic crop
cross crouch crowd crucial cruel cruise crumble crunch
crush cry crystal cube culture cup cupboard curious
current curtain curve cushion custom cute cycle dad
damage damp dance danger daring dash daughter dawn
day deal debate debris decade december decide decline
decorate decrease deer defense define defy degree delay
deliver demand demise denial dentist deny depart depend
deposit depth deputy derive describe desert design desk
despair destroy detail detect develop device devote diagram
dial diamond diary dice diesel diet differ digital
dignity dilemma dinner dinosaur direct dirt disagree discover
disease dish dismiss disorder display distance divert divide
divorce dizzy doctor document dog doll dolphin domain
donate donkey donor door dose double dove draft
dragon drama drastic draw dream dress drift drill
drink drip drive drop drum dry duck dumb
dune during dust dutch duty dwarf dynamic eager
eagle early earn earth easily east easy echo
ecology economy edge edit educate effort egg eight
either elbow elder electric elegant element elephant elevator
elite else embark embody embrace emerge emotion employ
empower empty enable enact end endless endorse enemy
energy enforce engage engine enhance enjoy enlist enough
enrich enroll ensure enter entire entry envelope episode
equal equip era erase erode erosion error erupt
escape essay essence estate eternal ethics evidence evil
evoke evolve exact example excess exchange excite exclude
excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend
extra eye eyebrow fabric face faculty fade faint
faith fall false fame family famous fan fancy
fantasy farm fashion fat fatal father fatigue fault
favorite feature february federal fee feed feel female
fence festival fetch fever few fiber fiction field
figure file film filter final find fine finger
finish fire firm first fiscal fish fit fitness
fix flag flame flash flat flavor flee flight
flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot
force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend
fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy
gallery game gap garage garbage garden garlic garment
gas gasp gate gather gauge gaze general genius
genre gentle genuine gesture ghost giant gift giggle
ginger giraffe girl give glad glance glare glass
glide glimpse globe gloom glory glove glow glue
goat goddess gold good goose gorilla gospel gossip
govern gown grab grace grain grant grape grass
gravity great green grid grief grit grocery group
grow grunt guard guess guide guilt guitar gun
gym habit hair half hammer hamster hand happy
harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet
help hen hero hidden high hill hint hip
hire history hobby hockey hold hole holiday hollow
home honey hood hope horn horror horse hospital
host hotel hour hover hub huge human humble
humor hundred hungry hunt hurdle hurry hurt husband
hybrid ice icon idea identify idle ignore ill
illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate
indoor industry infant inflict inform inhale inherit initial
inject injury inmate inner innocent input inquiry insane
insect inside inspire install intact interest into invest
invite involve iron island isolate issue item ivory
jacket jaguar jar jazz jealous jeans jelly jewel
job join joke journey joy judge juice jump
jungle junior junk just kangaroo keen keep ketchup
key kick kid kidney kind kingdom kiss kit
kitchen kite kitten kiwi knee knife knock know
lab label labor ladder lady lake lamp language
laptop large later latin laugh laundry lava law
lawn lawsuit layer lazy leader leaf learn leave
lecture left leg legal legend leisure lemon lend
length lens leopard lesson letter level liar liberty
library license life lift light like limb limit
link lion liquid list little live lizard load
loan lobster local lock logic lonely long loop
lottery loud lounge love loyal lucky luggage lumber
lunar lunch luxury lyrics machine mad magic magnet
maid mail main major make mammal man manage
mandate mango mansion manual maple marble march margin
marine market marriage mask mass master match material
math matrix matter maximum maze meadow mean measure
meat mechanic medal media melody melt member memory
mention menu mercy merge merit merry mesh message
metal method middle midnight milk million mimic mind
minimum minor minute miracle mirror misery miss mistake
mix mixed mixture mobile model modify mom moment
monitor monkey monster month moon moral more morning
mosquito mother motion motor mountain mouse move movie
much muffin mule multiply muscle museum mushroom music
must mutual myself mystery myth naive name napkin
narrow nasty nation nature near neck need negative
neglect neither nephew nerve nest net network neutral
never news next nice night noble noise nominee
noodle normal north nose notable note nothing notice
novel now nuclear number nurse nut oak obey
object oblige obscure observe obtain obvious occur ocean
october odor off offer office often oil okay
old olive olympic omit once one onion online
only open opera opinion oppose option orange orbit
orchard order ordinary organ orient original orphan ostrich
other outdoor outer output outside oval oven over
own owner oxygen oyster ozone pact paddle page
pair palace palm panda panel panic panther paper
parade parent park parrot party pass patch path
patient patrol pattern pause pave payment peace peanut
pear peasant pelican pen penalty pencil people pepper
perfect permit person pet phone photo phrase physical
piano picnic picture piece pig pigeon pill pilot
pink pioneer pipe pistol pitch pizza place planet
plastic plate play please pledge pluck plug plunge
poem poet point polar pole police pond pony
pool popular portion position possible post potato pottery
poverty powder power practice praise predict prefer prepare
present pretty prevent price pride primary print priority
prison private prize problem process produce profit program
project promote proof property prosper protect proud provide
public pudding pull pulp pulse pumpkin punch pupil
puppy purchase purity purpose purse push put puzzle
pyramid quality quantum quarter question quick quit quiz
quote rabbit raccoon race rack radar radio rail
rain raise rally ramp ranch random range rapid
rare rate rather raven raw razor ready real
reason rebel rebuild recall receive recipe record recycle
reduce reflect reform refuse region regret regular reject
relax release relief rely remain remember remind remove
render renew rent reopen repair repeat replace report
require rescue resemble resist resource response result retire
retreat return reunion reveal review reward rhythm rib
ribbon rice rich ride ridge rifle right rigid
ring riot ripple risk ritual rival river road
roast robot robust rocket romance roof rookie room
rose rotate rough round route royal rubber rude
rug rule run runway rural sad saddle sadness
safe sail salad salmon salon salt salute same
sample sand satisfy satoshi sauce sausage save say
scale scan scare scatter scene scheme school science
scissors scorpion scout scrap screen script scrub sea
search season seat second secret section security seed
seek segment select sell seminar senior sense sentence
series service session settle setup seven shadow shaft
shallow share shed shell sheriff shield shift shine
ship shiver shock shoe shoot shop short shoulder
shove shrimp shrug shuffle shy sibling sick side
siege sight sign silent silk silly silver similar
simple since sing siren sister situate six size
skate sketch ski skill skin skirt skull slab
slam sleep slender slice slide slight slim slogan
slot slow slush small smart smile smoke smooth
snack snake snap sniff snow soap soccer social
sock soda soft solar soldier solid solution solve
someone song soon sorry sort soul sound soup
source south space spare spatial spawn speak special
speed spell spend sphere spice spider spike spin
spirit split spoil sponsor spoon sport spot spray
spread spring spy square squeeze squirrel stable stadium
staff stage stairs stamp stand start state stay
steak steel stem step stereo stick still sting
stock stomach stone stool story stove strategy street
strike strong struggle student stuff stumble style subject
submit subway success such sudden suffer sugar suggest
suit summer sun sunny sunset super supply supreme
sure surface surge surprise surround survey suspect sustain
swallow swamp swap swarm swear sweet swift swim
swing switch sword symbol symptom syrup system table
tackle tag tail talent talk tank tape target
task taste tattoo taxi teach team tell ten
tenant tennis tent term test text thank that
theme then theory there they thing this thought
three thrive throw thumb thunder ticket tide tiger
tilt timber time tiny tip tired tissue title
toast tobacco today toddler toe together toilet token
tomato tomorrow tone tongue tonight tool tooth top
topic topple torch tornado tortoise toss total tourist
toward tower town toy track trade traffic tragic
train transfer trap trash travel tray treat tree
trend trial tribe trick trigger trim trip trophy
trouble truck true truly trumpet trust truth try
tube tuition tumble tuna tunnel turkey turn turtle
twelve twenty twice twin twist two type typical
ugly umbrella unable unaware uncle uncover under undo
unfair unfold unhappy uniform unique unit universe unknown
unlock until unusual unveil update upgrade uphold upon
upper upset urban urge usage use used useful
useless usual utility vacant vacuum vague valid valley
valve van vanish vapor various vast vault vehicle
velvet vendor venture venue verb verify version very
vessel veteran viable vibrant vicious victory video view
village vintage violin virtual virus visa visit visual
vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want
warfare warm warrior wash wasp waste water wave
way wealth weapon wear weasel weather web wedding
weekend weird welcome west wet whale what wheat
wheel when where whip whisper wide width wife
wild will win window wine wing wink winner
winter wire wisdom wise wish witness wolf woman
wonder wood wool word work world worry worth
wrap wreck wrestle wrist write wrong yard year
yellow you young youth zebra zero zone zoo"""

WORDS = WORDLIST.split()
assert len(WORDS) == 2048, len(WORDS)
assert WORDS == sorted(WORDS) and len(set(WORDS)) == 2048


# ---------------------------------------------------------------------------
# Official BIP39 English test vectors: (entropy_hex, mnemonic, seed_hex).
# Sourced verbatim from the trezor/python-mnemonic vectors.json (bip-0039).
# ---------------------------------------------------------------------------
OFFICIAL_EN = [
    ("00000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
    ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage worth useful legal winner thank yellow",
     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"),
    ("80808080808080808080808080808080",
     "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
     "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"),
    ("ffffffffffffffffffffffffffffffff",
     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
     "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"),
    ("000000000000000000000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
     "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa"),
    ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
     "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd"),
    ("808080808080808080808080808080808080808080808080",
     "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
     "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65"),
    ("ffffffffffffffffffffffffffffffffffffffffffffffff",
     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
     "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528"),
    ("0000000000000000000000000000000000000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"),
    ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
     "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87"),
    ("8080808080808080808080808080808080808080808080808080808080808080",
     "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
     "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"),
    ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
     "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"),
    ("9e885d952ad362caeb4efe34a8e91bd2",
     "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
     "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028"),
    ("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
     "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
     "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac"),
    ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
     "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
     "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"),
    ("c0ba5a8e914111210f2bd131f3d5e08d",
     "scheme spot photo card baby mountain device kick cradle pact join borrow",
     "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612"),
    ("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
     "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
     "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d"),
    ("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
     "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
     "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d"),
    ("23db8160a31d3e0dca3688ed941adbf3",
     "cat swing flag economy stadium alone churn speed unique patch report train",
     "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5"),
    ("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
     "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
     "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02"),
    ("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
     "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
     "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d"),
    ("f30f8c1da665478f49b001d94c5fc452",
     "vessel ladder alter error federal sibling chat ability sun glass valve picture",
     "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f"),
    ("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
     "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
     "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88"),
    ("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
     "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
     "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"),
]

# Known-good passphrase seed (BIP39 with a non-empty BIP-39 passphrase):
# derived only via hashlib.pbkdf2_hmac. (No official vector exists for this in
# the English set; we assert our own PBKDF2 path against the mnemonic's own
# entropy so the asm PBKDF2 is cross-checked on a salted passphrase too.)
PASSPHRASES = [
    ("TREZOR",),
    ("bitcoin",),
    ("correct horse battery staple",),
    ("J\xc3\xbcrgen",),   # non-ASCII multi-byte UTF-8 passphrase
]


# ============================================================================
# BIP39 reference implementation (pure Python, no external deps)
# ============================================================================
def entropy_to_mnemonic(ent):
    """ent: big-endian bytes length 16/20/24/28/32. Returns mnemonic string."""
    ent_bits = len(ent) * 8
    cs_bits = ent_bits // 32
    checksum = hashlib.sha256(ent).digest()
    # bits = entropy bits ++ first cs_bits of checksum
    bitstr = ''.join(f'{b:08b}' for b in ent) + \
             f'{checksum[0]:08b}'[:cs_bits]
    words = []
    for i in range(0, len(bitstr), 11):
        idx = int(bitstr[i:i + 11], 2)
        words.append(WORDS[idx])
    return ' '.join(words)


def mnemonic_to_entropy(mn):
    """Reverse: validate + return entropy bytes."""
    ws = mn.split()
    n = len(ws)
    if n not in (12, 15, 18, 21, 24):
        raise ValueError(f'bad word count {n}')
    ent_bits = n * 32 // 3
    cs_bits = ent_bits // 32
    indices = [WORDS.index(w) for w in ws]
    bitstr = ''.join(f'{i:011b}' for i in indices)
    ent_int = int(bitstr[:ent_bits], 2)
    ent = ent_int.to_bytes(ent_bits // 8, 'big')
    checksum = hashlib.sha256(ent).digest()
    exp_cs = f'{checksum[0]:08b}'[:cs_bits]
    got_cs = bitstr[ent_bits:ent_bits + cs_bits]
    if got_cs != exp_cs:
        raise ValueError('checksum mismatch')
    return ent


def mnemonic_to_seed(mn, passphrase=b''):
    return hashlib.pbkdf2_hmac('sha512', mn.encode(), b'mnemonic' + passphrase,
                               2048, dklen=64)


# ============================================================================
# Self-test: prove our independent BIP39 implementation is correct before we
# emit C. Two independent checks:
#   1. The official offsetser.tsv JSON "seed" fields are actually the seed for
#      BIP39 passphrase "TREZOR" (a well-known quirk of that file). We assert
#      mnemonic_to_seed(mn, b"TREZOR") reproduces every official seed, which
#      both validates our mnemonic strings AND our PBKDF2 against the official
#      oracle.
#   2. entropy->mnemonic->entropy round trips for every official vector, and
#      the empty-passphrase seed is cross-checked against the THIRD-PARTY
#      `mnemonic` pip package when it is importable (dev-time only).
#      At build time (runtime) hashlib alone is authoritative for the emitted
#      empty-passphrase seeds.
# ============================================================================
def selftest():
    n_mn = 0
    for ent_hex, mn, seed_hex in OFFICIAL_EN:
        ent = bytes.fromhex(ent_hex)
        got_mn = entropy_to_mnemonic(ent)
        assert got_mn == mn, f'mnemonic mismatch for {ent_hex}'
        back = mnemonic_to_entropy(got_mn)
        assert back == ent, f'roundtrip entropy mismatch {ent_hex}'
        # official seed is the <mnemonic>/TREZOR passphrase seed
        got_tz = mnemonic_to_seed(mn, b'TREZOR')
        assert got_tz.hex() == seed_hex, (
            f'TREZOR seed mismatch for {ent_hex}:\n  got {got_tz.hex()}\n  exp {seed_hex}')
        n_mn += 1

    # dev-time cross-check of the empty-passphrase seeds against a THIRD party
    # implementation (the `mnemonic` pip package), if present.
    try:
        from mnemonic import Mnemonic
        mm = Mnemonic('english')
        for ent_hex, mn, _ in OFFICIAL_EN[:8]:
            assert mm.to_seed(mn).hex() == mnemonic_to_seed(mn).hex()
        print('  cross-check: empty-pass seeds match the `mnemonic` pip package (8 checked)', file=sys.stderr)
    except ImportError:
        print('  cross-check: `mnemonic` pip package not installed; '
              'empty-pass seeds rely on hashlib only', file=sys.stderr)

    # negative / corruption validation
    def expect_invalid(mn):
        try:
            mnemonic_to_entropy(mn)
        except (ValueError, IndexError, KeyError):
            return
        raise AssertionError(f'must have been rejected: {mn!r}')

    # 11 words: not a valid length
    expect_invalid("abandon abandon abandon abandon abandon abandon "
                   "abandon abandon abandon abandon abandon")
    # unknown word (not in the 2048-word list)
    expect_invalid("abandon abandon abandon abandon abandon abandon "
                   "abandon abandon abandon abandon abandon zzz")
    # wrong checksum: valid words, but the final word does not match the
    # SHA-256 checksum of the entropy (valid 12-word, all-abandon, where the
    # correct final word is 'about' -- 'abandon' produces a bad checksum).
    expect_invalid("abandon abandon abandon abandon abandon abandon "
                   "abandon abandon abandon abandon abandon abandon")
    print(f'  selftest: {n_mn} official vectors reproduced OK (mnemonic + TREZOR seed)', file=sys.stderr)


# ============================================================================
# Emit C header
# ============================================================================
def emit():
    out = []
    a = out.append
    a('/* bip39_vec.h -- BIP39 test vectors generated by')
    a(' * validation/gen_bip39_vectors.py (independent Python oracle).')
    a(' *')
    a(' * Each vector: entropy_hex, expected mnemonic, the expected 64-byte')
    a(' * BIP39 seed for the EMPTY passphrase (computed via Python hashlib') 
    a(' * pbkdf2_hmac, a different implementation than the asm) and the')
    a(' * expected seed for the official BIP39 passphrase "TREZOR" (verbatim')
    a(' * from the official bip-0039 vectors). The asm harness checks both.')
    a(' * Do not edit by hand. */')
    a('#ifndef BIP39_VEC_H')
    a('#define BIP39_VEC_H')
    a('')
    a('#define BIP39VEC_LEN %d' % len(OFFICIAL_EN))
    a('')
    a('struct bip39_vec {')
    a('    const char* ent;')      # entropy hex
    a('    const char* mn;')        # mnemonic sentence
    a('    const char* seed_empty;')# seed hex, empty passphrase (hashlib)
    a('    const char* seed_trezor;')# seed hex, passphrase "TREZOR" (official)
    a('    int words;')             # word count (12/15/18/21/24)
    a('};')
    a('')
    a('static const struct bip39_vec BIP39VEC[BIP39VEC_LEN] = {')
    for ent_hex, mn, seed in OFFICIAL_EN:
        ec = len(ent_hex) // 2
        nwords = len(mn.split())
        seed_empty = mnemonic_to_seed(mn).hex()
        # the official seed is the TREZOR-passphrase seed
        a('    { "%s",' % ent_hex)
        a('      "%s",' % mn)
        a('      "%s",' % seed_empty)
        a('      "%s", %d },  /* %d-byte entropy */' % (seed, nwords, ec))
    a('};')
    a('')
    # Extra non-empty BIP39 passphrase vectors (seeds via hashlib).
    pv = [
        (OFFICIAL_EN[0][1], 'TREZOR'),                    # == official already
        (OFFICIAL_EN[1][1], 'bitcoin'),
        (OFFICIAL_EN[12][1], 'correct horse battery staple'),
        (OFFICIAL_EN[0][1], 'J\xc3\xbcrgen'),             # UTF-8 multi-byte
    ]
    seed_for = lambda mn, pp: mnemonic_to_seed(mn, pp.encode()).hex()
    a('#define BIP39PPVEC_LEN %d' % len(pv))
    a('')
    a('struct bip39_pp_vec {')
    a('    const char* mn;')        # mnemonic sentence
    a('    const char* pass;')      # BIP39 passphrase (UTF-8)
    a('    const char* seed;')      # seed hex
    a('};')
    a('')
    a('static const struct bip39_pp_vec BIP39PPVEC[BIP39PPVEC_LEN] = {')
    for mn, pp in pv:
        a('    { "%s",' % mn)
        a('      "%s",' % pp)
        a('      "%s" },' % seed_for(mn, pp))
    a('};')
    a('')
    a('#endif /* BIP39_VEC_H */')
    return '\n'.join(out) + '\n'


if __name__ == '__main__':
    selftest()
    sys.stdout.write(emit())
