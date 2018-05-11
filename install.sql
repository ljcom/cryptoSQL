drop FUNCTION [gen].generateKeys
drop FUNCTION [gen].retrievePublicKey
drop FUNCTION [gen].getSignature
drop FUNCTION [gen].verifySignature
drop FUNCTION [gen].getSharedSecret
drop FUNCTION [gen].getDerivedKey
drop FUNCTION [gen].encrypt2F
drop FUNCTION [gen].decrypt2F
drop FUNCTION [gen].encryptAES
drop FUNCTION [gen].decryptAES
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
create FUNCTION [gen].encrypt2F(@m nvarchar(max), @p nvarchar(100), @s nvarchar(100))
RETURNS nvarchar(100) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].encrypt2F
go
create FUNCTION [gen].decrypt2F(@m nvarchar(max), @p nvarchar(100), @s nvarchar(100))
RETURNS nvarchar(100) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].decrypt2F
go
create FUNCTION [gen].encryptAES(@m nvarchar(max), @k nvarchar(100), @s nvarchar(100))
RETURNS nvarchar(100) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].encryptAES
go
create FUNCTION [gen].decryptAES(@m nvarchar(max), @k nvarchar(100), @s nvarchar(100))
RETURNS nvarchar(max) WITH EXECUTE AS CALLER
AS 
EXTERNAL NAME cryptoSQL.[cryptoSQL.functions].decryptAES
go