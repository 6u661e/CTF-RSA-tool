from Crypto.Util.number import getPrime, isPrime, bytes_to_long, long_to_bytes
# from data import flag, hint
# from sympy import nextprime
from gmpy2 import iroot, invert


hint = "get root"
# m = bytes_to_long(bytes(flag, encoding='utf-8'))

# p = getPrime(1024)

# q = nextprime(p)
# r = nextprime(q)
# n = p*q
# phi = (p-1)*(q-1)

# e = 0x10001

# d = invert(e, phi)
# c = pow(m, e, n)
# dp = d % (p-1)
# dq = d % (q-1)


# c= 29481634166275444081755526650435050746177271929108540340839636645290382212801883156176249297905065394477723980727035074018048212479803055923507504121830977544547768817541693745091881774043457256431594076739380675412845360130106309932588508902347792967474645133565825400509525159035854284711152310367992325935
# dp= 8488018598582161778909675874955311952104108410770019733352933135643797561752804534164335792268466126138022884715691928735179876112592458061466852929011221
# dq= 1804557936862041610503694621208928380602760766763762174784442626117998593478392526552839638322965598840334590533505416988939157674783742124641579057347585


# # ------------------------------------------------------


# P_ = nextprime(phi)
# Q_ = getPrime(512)


# N_ = P_*Q_
# PHI_ = (P_-1)*(Q_-1)
# M_ = bytes_to_long(bytes(hint, encoding='utf-8'))

# E_ = 0x10001
# D_ = invert(E_, PHI_)
# C_ = pow(M_, E_, N_)

# print("C_=", C_)
# print("N_=", N_)
# print("PHI_=", PHI_)

E_ = 0x10001
C_ = 167991288045303000655678332469702456156006927056795988184486782639594811154157430883888171768898616013017469226146528316669411009693161813068877601341794154799154579698061130344409936572057393406182997791983691902804474594459551816221476117792337686268697787228149355295256968844786104832801764130261045846806268887759441150366851268084155967124558636130241419050274900078069517490749660442582935909745378880450868778768818202112172222446341661337699089743565266
N_ = 1141574900469012067636252180723835763151920736282470632700965427450254174708499891391924201142298374181693031433288816864153023177804715482450166860015258287506501285068163017195211966134698458111181058182005585938681465830111118867709096243399041372276386809721333892464112085735367452600541715292290079220522270815111077388426606567096816463177229069700881806969035414147663217609196771833717652147248133905228806566277089964340350926709132880091484440081291867
PHI_ = 1141574900469012067636252180723835763151920736282470632700965427450254174708499891391924201142298374181693031433288816864153023177804715482450166860015258165887575210803576766535149248650990306655744681050265422300794686668511098707335740896061248758188315389043730123141479632359506080499922725994127962549611715479724233268459284756489870354300620746588895051518136083710196648747569108450588260775600203396574920477102242310852948444452793222038768500472297680
D_ = invert(E_, PHI_)
print(long_to_bytes(pow(C_, D_, N_)))
