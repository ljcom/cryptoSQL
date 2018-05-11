# cryptoSQL

Requires bouncycastle source code

Scripts: run install.sql

Test:


select gen.generateKeys('256', 'live') 

Result (in xml):
<sqroot>
  <D>79652952858629156686989295468020039736032885168632888013045554148505071878668</D>
  <Q>BMqirILraEjectk8whU+j3W6w6Rho1feX2XfQJ1XNkhJ9he+iRl6GPrwRQ9WaXjOssvDnrDBYojTYPFVPh/2i1k=</Q>
  <A>0xE6F890E92811E9025A1A35FB071D4FB90EC5F4B8C31A98D399BB70CA0C948354</A>
</sqroot>
<sqroot>
  <D>72733876154275384066709918005567644465438873797268030115622394322457098305076</D>
  <Q>BL99d3H363zhg16WWhYW6b0O+vTEOAUUFFNJWHHhtaK9VvXut2zd5bXeh/Unq2JXx/S1FovztxobM+Bh52d6JFQ=</Q>
  <A>0x38C457CCCF3C0D006E682A5037530160F0A044F768D142EC6995461B05E9CC9B</A>
</sqroot>


select gen.retrievePublicKey(256, '110416795997305598133421621358658288015115081350651885789140442269499744100673')

Result:
BABfeyLaBh48Eb9J9pIAMYNOE6hp0WJo2QXMC2xbPvs+dXAbC7dywxMGdpT5YWx0Z8xhYkiaRvbsDGthIpHYkDw=

select gen.retrievePublicKey(256, '91562037688146674202535976746669402021923751585934680899649686131368369951230')

Result:
BF4waypJ8UnXxoFk1sRG+dNheZmlO9KvIlbTNy4ZfsxQzBbIhqF+dWL2tuvFkTGek2zP8Q1rgMGNL5iP5nY3pbg=

select gen.GetSignature('256', '110416795997305598133421621358658288015115081350651885789140442269499744100673', 'this is the real document')

Result:
MEUCIQDcl8TLOB41du4f2OKnshiEpOm7i9uetBvWpBChPRgtSgIgXltdjYF+/tOUS2s3CQ52DBqOgM+MrUIn9TC8OMOpEJc=


select gen.VerifySignature('256', 'BOyK0jPIZIL7sw3+0hkQ4wsSZyYvGpW1B6drvupTYlc4prlcrj9X1xByycIEARr0pHWZRdZGV9uRCIYD4D5rjEE=', 'this is the real document', 'MEUCIQDcl8TLOB41du4f2OKnshiEpOm7i9uetBvWpBChPRgtSgIgXltdjYF+/tOUS2s3CQ52DBqOgM+MrUIn9TC8OMOpEJc=')

Result:
1


select gen.getSharedSecret('256', '79652952858629156686989295468020039736032885168632888013045554148505071878668', 'BL99d3H363zhg16WWhYW6b0O+vTEOAUUFFNJWHHhtaK9VvXut2zd5bXeh/Unq2JXx/S1FovztxobM+Bh52d6JFQ=')
select gen.getSharedSecret('256', '72733876154275384066709918005567644465438873797268030115622394322457098305076', 'BMqirILraEjectk8whU+j3W6w6Rho1feX2XfQJ1XNkhJ9he+iRl6GPrwRQ9WaXjOssvDnrDBYojTYPFVPh/2i1k=')

Result:
UQJM7ngqqR3JE4IbB8Ii0Jfgkyps+Rc7bRTC05Ni888=

select gen.getDerivedKey('UQJM7ngqqR3JE4IbB8Ii0Jfgkyps+Rc7bRTC05Ni888=')

Result:
wgBpD5ouUhBHcJHWAevlOcmIV3Y5FJw7T3D417m1nPk=

select gen.encryptAES('This is the TOP secret', 'UQJM7ngqqR3JE4IbB8Ii0Jfgkyps+Rc7bRTC05Ni888=', 'wgBpD5ouUhBHcJHWAevlOcmIV3Y5FJw7T3D417m1nPk=')

Result:
8E5pKoHB+zwkFH8euTjFWubyfbe7nNOva0pyBQeSAaY=

select gen.decryptAES('8E5pKoHB+zwkFH8euTjFWubyfbe7nNOva0pyBQeSAaY=', 'UQJM7ngqqR3JE4IbB8Ii0Jfgkyps+Rc7bRTC05Ni888=', 'wgBpD5ouUhBHcJHWAevlOcmIV3Y5FJw7T3D417m1nPk=')

Result:
This is the TOP secret





