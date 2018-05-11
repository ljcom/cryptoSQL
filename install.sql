if exists(select * from sys.objects where name='generateKeys') drop FUNCTION [gen].generateKeys
if exists(select * from sys.objects where name='retrievePublicKey') drop FUNCTION [gen].retrievePublicKey
if exists(select * from sys.objects where name='getSignature') drop FUNCTION [gen].getSignature
if exists(select * from sys.objects where name='verifySignature') drop FUNCTION [gen].verifySignature
if exists(select * from sys.objects where name='getSharedSecret') drop FUNCTION [gen].getSharedSecret
if exists(select * from sys.objects where name='getDerivedKey') drop FUNCTION [gen].getDerivedKey
if exists(select * from sys.objects where name='encrypt2F') drop FUNCTION [gen].encrypt2F
if exists(select * from sys.objects where name='decrypt2F') drop FUNCTION [gen].decrypt2F
if exists(select * from sys.objects where name='encryptAES') drop FUNCTION [gen].encryptAES
if exists(select * from sys.objects where name='decryptAES') drop FUNCTION [gen].decryptAES
go

create FUNCTION [gen].[generateKeys](@key nvarchar(4), @network nvarchar(10))
RETURNS xml WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].[generateKeys]
go
create FUNCTION [gen].retrievePublicKey(@key nvarchar(4), @prv nvarchar(100))
RETURNS nvarchar(100) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].[retrievePublicKey]
go

create FUNCTION [gen].GetSignature(@key nvarchar(4), @prv nvarchar(100), @msg nvarchar(max))
RETURNS nvarchar(max) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].getSignature

go

create FUNCTION [gen].VerifySignature(@key nvarchar(4), @pub nvarchar(100), @msg nvarchar(max), @sig nvarchar(max))
RETURNS bit WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].verifySignature
go
create FUNCTION [gen].getSharedSecret(@key nvarchar(4), @prv nvarchar(100), @pub nvarchar(100))
RETURNS nvarchar(100) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].getSharedSecret
go
create FUNCTION [gen].getDerivedKey(@ss nvarchar(100))
RETURNS nvarchar(100) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].getDerivedKey
go
create FUNCTION [gen].encrypt2F(@m nvarchar(max), @p nvarchar(max), @s nvarchar(max))
RETURNS nvarchar(max) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].encrypt2F
go
create FUNCTION [gen].decrypt2F(@m nvarchar(max), @p nvarchar(max), @s nvarchar(max))
RETURNS nvarchar(max) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].decrypt2F
go
create FUNCTION [gen].encryptAES(@m nvarchar(max), @k nvarchar(max), @s nvarchar(max))
RETURNS nvarchar(max) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].encryptAES
go
create FUNCTION [gen].decryptAES(@m nvarchar(max), @k nvarchar(max), @s nvarchar(max))
RETURNS nvarchar(max) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].decryptAES
go