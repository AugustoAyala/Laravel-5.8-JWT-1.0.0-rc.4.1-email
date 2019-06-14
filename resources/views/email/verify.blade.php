<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="utf-8">
</head>
<body>

<div>
    Hola {{ $name }},
    <br>
    Gracias por crear una cuenta con nosotros. No olvides completar tu registro
    <br>
    Haga clic en el enlace a continuación o cópielo en la barra de direcciones de su navegador para confirmar su dirección de correo electrónico:
    <br>

    <a href="{{ url('user/verify', $verification_code)}}">Confirmar mi dirección de correo electrónico </a>

    <br/>
</div>

</body>
</html>