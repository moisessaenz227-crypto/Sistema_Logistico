import base64
import hashlib
import hmac
import os
import secrets
import smtplib
from email.message import EmailMessage
from datetime import date, datetime, timedelta, timezone
from typing import List, Optional
from fpdf import FPDF
from cryptography.fernet import Fernet
import jwt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, text
from sqlalchemy.exc import IntegrityError

from app.database import get_db
from app import models, schemas

app = FastAPI(title="Sistema Logistico - API")


# ---------------- CONFIGURACIÓN ----------------

# IVA vigente. Cada Routing guarda su PROPIA copia al crearse, así que si esta tasa
# cambia en el futuro, los Routing anteriores no se alteran.
IVA_VIGENTE = 15.0

# Cuántas veces se "revuelve" la contraseña al cifrarla. Más vueltas = más difícil de adivinar.
ITERACIONES_HASH = 200_000

# Clave secreta con la que se FIRMAN los tokens de sesión (viene del archivo .env).
SECRET_KEY = os.getenv("SECRET_KEY", "clave-de-desarrollo-cambiala-en-el-env")
ALGORITMO_JWT = "HS256"
TOKEN_MINUTOS = 480  # la sesión dura 8 horas

# Credenciales del correo (van en el .env; si faltan, el envío avisa claro y no revienta).
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)


# Llave maestra para cifrar datos sensibles guardados en la base de datos (viene del .env).
ENCRYPTION_KEY_RAW = os.getenv("ENCRYPTION_KEY")
_fernet = Fernet(ENCRYPTION_KEY_RAW.encode()) if ENCRYPTION_KEY_RAW else None

# Estas claves de configuración se guardan CIFRADAS en la base de datos.
CLAVES_SENSIBLES = {"SMTP_PASSWORD"}


def _config_obtener(db: Session, clave: str, default=None):
    """Lee un valor de configuración. Si no está en la base de datos, usa el .env o el default."""
    fila = db.query(models.Configuracion).filter(models.Configuracion.clave == clave).first()
    if fila is None:
        return os.getenv(clave, default)

    valor = fila.valor
    if clave in CLAVES_SENSIBLES and _fernet is not None:
        try:
            valor = _fernet.decrypt(valor.encode()).decode()
        except Exception:
            return default
    return valor


def _config_guardar(db: Session, clave: str, valor: str):
    """Crea o actualiza un valor de configuración. Si la clave es sensible, se guarda cifrado."""
    if clave in CLAVES_SENSIBLES:
        if _fernet is None:
            raise HTTPException(
                status_code=400,
                detail="Falta ENCRYPTION_KEY en el .env para poder guardar valores sensibles",
            )
        valor_a_guardar = _fernet.encrypt(valor.encode()).decode()
    else:
        valor_a_guardar = valor

    fila = db.query(models.Configuracion).filter(models.Configuracion.clave == clave).first()
    if fila is None:
        fila = models.Configuracion(clave=clave, valor=valor_a_guardar)
        db.add(fila)
    else:
        fila.valor = valor_a_guardar

    db.commit()
    db.refresh(fila)
    return fila


def _iva_vigente(db: Session) -> float:
    """El IVA guardado en Configuracion (clave IVA_PORCENTAJE), o 15.0 si todavia no se configuro."""
    valor = _config_obtener(db, "IVA_PORCENTAJE", str(IVA_VIGENTE))
    try:
        return float(valor)
    except (TypeError, ValueError):
        return IVA_VIGENTE

    
# ---------------- UTILIDADES ----------------

def _nombre(db: Session, clase: str, registro_id):
    """Nombre legible de un registro de catálogo (ej. _nombre(db, "Buques", 1) -> "WAN HAI A06")."""
    if registro_id is None:
        return None
    modelo = getattr(models, clase)
    fila = db.query(modelo).filter(modelo.id == registro_id).first()
    return fila.nombre if fila is not None else None


def _rol_de(db: Session, usuario: models.Usuarios) -> Optional[str]:
    """El nombre del rol de un usuario (ej. 'COMERCIAL'), o None si no tiene."""
    if usuario.rol_id is None:
        return None
    rol = db.query(models.Roles).filter(models.Roles.id == usuario.rol_id).first()
    return rol.nombre if rol is not None else None


def _correo_de_usuario(db: Session, usuario_id):
    """Correo del trabajador ligado a un usuario cualquiera (o None)."""
    if usuario_id is None:
        return None
    usuario = db.query(models.Usuarios).filter(models.Usuarios.id == usuario_id).first()
    if usuario is None:
        return None
    trabajador = db.query(models.Trabajadores).filter(
        models.Trabajadores.id == usuario.trabajador_id
    ).first()
    return trabajador.correo if trabajador is not None else None


# ---------------- PERMISOS ----------------

VER, CREAR, EDITAR, ELIMINAR, JALAR, NOTIFICAR = "ver", "crear", "editar", "eliminar", "jalar", "notificar"
TODO = {VER, CREAR, EDITAR, ELIMINAR}

PERMISOS = {
    "seguridad": {
        "ADMINISTRADOR": TODO,
    },
        "configuracion": {
        "ADMINISTRADOR": TODO,
    },    
    "companias": {
        "ADMINISTRADOR": TODO,
        "OPERACIONES": {VER, CREAR, EDITAR},
        "COMERCIAL": {VER, CREAR},
        "CUSTOMER": {VER, CREAR},
    },
    "maestros": {
        "ADMINISTRADOR": TODO,
        "OPERACIONES": {VER, CREAR, EDITAR},
        "COMERCIAL": {VER},
        "CUSTOMER": {VER},
    },
    "cotizaciones": {
        "ADMINISTRADOR": TODO | {JALAR},
        "OPERACIONES": TODO | {JALAR},
        "COMERCIAL": {VER, CREAR, EDITAR, ELIMINAR},  # solo las suyas (se revisa aparte)
        "CUSTOMER": {VER, JALAR},                      # solo las suyas (se revisa aparte)
    },
    "routing": {
        "ADMINISTRADOR": TODO,
        "OPERACIONES": TODO,
        "COMERCIAL": {VER, EDITAR, ELIMINAR},  # solo los suyos (se revisa aparte)
        "CUSTOMER": {VER, EDITAR, ELIMINAR},   # solo los suyos (se revisa aparte)
    },
    "itinerario": {
        "ADMINISTRADOR": TODO,
        "OPERACIONES": {VER, CREAR, EDITAR},
        "CUSTOMER": {VER},
    },
    "bl": {
        "ADMINISTRADOR": TODO,
        "OPERACIONES": {VER, CREAR, EDITAR},
        "CUSTOMER": {VER},
    },
    "aviso": {
        "ADMINISTRADOR": {VER, NOTIFICAR},
        "OPERACIONES": {VER, NOTIFICAR},
        "CUSTOMER": {VER, NOTIFICAR},  # solo de sus Routing (se revisa aparte)
    },
}


# ---------------- AUTENTICACIÓN (LOGIN) ----------------

def _hash_password(password: str) -> str:
    """Cifra la contraseña. Es de UNA sola vía: se puede comprobar, pero no descifrar."""
    sal = secrets.token_bytes(16)
    derivada = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), sal, ITERACIONES_HASH)
    return f"{base64.b64encode(sal).decode()}${base64.b64encode(derivada).decode()}"


def _verificar_password(password: str, guardado: str) -> bool:
    """Comprueba una contraseña: la cifra con LA MISMA sal guardada y compara los resultados."""
    try:
        sal_b64, hash_b64 = guardado.split("$")
        sal = base64.b64decode(sal_b64)
        esperado = base64.b64decode(hash_b64)
    except Exception:
        return False
    derivada = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), sal, ITERACIONES_HASH)
    return hmac.compare_digest(derivada, esperado)


def _crear_token(usuario_id: int) -> str:
    """Crea el 'carnet' de sesión: lleva el id del usuario y una fecha de vencimiento, y va FIRMADO."""
    vence = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTOS)
    return jwt.encode({"sub": str(usuario_id), "exp": vence}, SECRET_KEY, algorithm=ALGORITMO_JWT)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def usuario_actual(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Lee el token que manda el navegador y devuelve el usuario que inició sesión."""
    sesion_invalida = HTTPException(
        status_code=401,
        detail="Sesión inválida o vencida. Inicia sesión de nuevo.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        datos = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITMO_JWT])
        usuario_id = int(datos["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise sesion_invalida

    usuario = db.query(models.Usuarios).filter(models.Usuarios.id == usuario_id).first()
    if usuario is None or not usuario.activo:
        raise sesion_invalida
    return usuario


def requiere(modulo: str, accion: str):
    """Crea una dependencia: solo deja pasar si el ROL del usuario tiene esa acción en ese módulo."""

    def _verificar(
        usuario: models.Usuarios = Depends(usuario_actual), db: Session = Depends(get_db)
    ) -> models.Usuarios:
        rol = _rol_de(db, usuario)
        permitido = PERMISOS.get(modulo, {}).get(rol, set())
        if accion not in permitido:
            raise HTTPException(
                status_code=403,
                detail=f"Tu rol ({rol}) no tiene permiso para '{accion}' en '{modulo}'",
            )
        return usuario

    return _verificar


@app.post("/auth/login", response_model=schemas.TokenRead)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    usuario = db.query(models.Usuarios).filter(
        models.Usuarios.usuario == form.username.strip().lower()
    ).first()

    if (
        usuario is None
        or not usuario.activo
        or not _verificar_password(form.password, usuario.password_hash)
    ):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    return {"access_token": _crear_token(usuario.id), "token_type": "bearer"}


@app.get("/auth/yo", response_model=schemas.UsuarioRead)
def quien_soy(usuario=Depends(usuario_actual), db: Session = Depends(get_db)):
    """Datos del usuario que inició sesión (con su rol). Cualquiera que inició sesión puede verlo."""
    usuario.rol = _nombre(db, "Roles", usuario.rol_id)
    usuario.trabajador = _nombre(db, "Trabajadores", usuario.trabajador_id)
    return usuario


# ---------------- SISTEMA ----------------

@app.get("/")
def home():
    return {"mensaje": "API corriendo correctamente"}


@app.get("/salud-db")
def salud_db(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"base_de_datos": "conectada"}


# ---------------- COMPAÑÍAS ----------------

@app.post("/companias", response_model=schemas.CompaniaRead)
def crear_compania(
    compania: schemas.CompaniaCreate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("companias", CREAR)),
):
    nueva = models.Companias(**compania.model_dump())
    db.add(nueva)
    db.commit()
    db.refresh(nueva)
    return nueva


@app.get("/companias", response_model=List[schemas.CompaniaRead])
def listar_companias(db: Session = Depends(get_db), actor=Depends(requiere("companias", VER))):
    return db.query(models.Companias).all()


@app.put("/companias/{compania_id}", response_model=schemas.CompaniaRead)
def editar_compania(
    compania_id: int,
    datos: schemas.CompaniaUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("companias", EDITAR)),
):
    compania = db.query(models.Companias).filter(models.Companias.id == compania_id).first()
    if compania is None:
        raise HTTPException(status_code=404, detail="Compañía no encontrada")

    cambios = datos.model_dump(exclude_unset=True)
    for campo, valor in cambios.items():
        if valor is not None:
            setattr(compania, campo, valor)

    db.commit()
    db.refresh(compania)
    return compania


@app.delete("/companias/{compania_id}")
def eliminar_compania(
    compania_id: int, db: Session = Depends(get_db), actor=Depends(requiere("companias", ELIMINAR))
):
    compania = db.query(models.Companias).filter(models.Companias.id == compania_id).first()
    if compania is None:
        raise HTTPException(status_code=404, detail="Compañía no encontrada")

    try:
        db.delete(compania)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="No se puede eliminar: esta compañía ya está usada en cotizaciones, Routing o BL.",
        )
    return {"eliminado": True}


# ---------------- COTIZACIONES ----------------

def _es_mia_cotizacion(db: Session, usuario: models.Usuarios, cotizacion: models.Cotizacion) -> bool:
    rol = _rol_de(db, usuario)
    if rol in ("ADMINISTRADOR", "OPERACIONES"):
        return True
    if rol == "COMERCIAL":
        return cotizacion.usuario_creador_id == usuario.id
    if rol == "CUSTOMER":
        return cotizacion.usuario_customer_id == usuario.id
    return False


def _generar_pdf_cotizacion(db: Session, cotizacion: models.Cotizacion) -> bytes:
    """PDF de una pagina con el detalle de la Cotizacion (para el correo a la Customer)."""
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(20, 60, 120)
    pdf.cell(0, 10, f"COTIZACION #{cotizacion.id}", ln=True)
    pdf.set_draw_color(20, 60, 120)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    filas = [
        ("Cliente", _nombre(db, "Companias", cotizacion.compania_cliente_id)),
        ("Agente", _nombre(db, "Companias", cotizacion.agente_id)),
        ("Incoterm", _nombre(db, "Incoterms", cotizacion.incoterm_id)),
        ("Shipper", cotizacion.shipper_nombre),
        ("País de origen", _nombre(db, "Paises", cotizacion.pais_origen_id)),
        ("Puerto de origen", _nombre(db, "Puertos", cotizacion.puerto_origen_id)),
        ("Estado", cotizacion.estado),
    ]
    pdf.set_text_color(0, 0, 0)
    for etiqueta, valor in filas:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(50, 8, f"{etiqueta}:")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, str(valor) if valor else "-", ln=True)

    valores = db.query(models.CotizacionValores).filter(
        models.CotizacionValores.cotizacion_id == cotizacion.id
    ).all()
    if valores:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(20, 60, 120)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(80, 8, "Rubro", border=1, fill=True)
        pdf.cell(40, 8, "Compra", border=1, fill=True, align="R")
        pdf.cell(40, 8, "Venta", border=1, fill=True, align="R", ln=True)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 11)
        for v in valores:
            pdf.cell(80, 8, _nombre(db, "Rubros", v.rubro_id) or "-", border=1)
            pdf.cell(40, 8, f"{v.compra:.2f}", border=1, align="R")
            pdf.cell(40, 8, f"{v.venta:.2f}", border=1, align="R", ln=True)

    return bytes(pdf.output())


@app.post("/cotizaciones", response_model=schemas.CotizacionRead)
def crear_cotizacion(
    cotizacion: schemas.CotizacionCreate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("cotizaciones", CREAR)),
):
    datos = cotizacion.model_dump(exclude={"valores"})
    nueva = models.Cotizacion(**datos, usuario_creador_id=actor.id)
    db.add(nueva)
    db.commit()
    db.refresh(nueva)

    for valor in cotizacion.valores:
        db.add(models.CotizacionValores(cotizacion_id=nueva.id, **valor.model_dump()))
    db.commit()
    db.refresh(nueva)
    return nueva@app.post("/cotizaciones", response_model=schemas.CotizacionRead)
def crear_cotizacion(
    cotizacion: schemas.CotizacionCreate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("cotizaciones", CREAR)),
):
    datos = cotizacion.model_dump(exclude={"valores"})
    nueva = models.Cotizacion(**datos, usuario_creador_id=actor.id)
    db.add(nueva)
    db.commit()
    db.refresh(nueva)

    for valor in cotizacion.valores:
        db.add(models.CotizacionValores(cotizacion_id=nueva.id, **valor.model_dump()))
    db.commit()
    db.refresh(nueva)

    # Correo a la Customer con el PDF adjunto. Si falla o no hay SMTP, NO se bloquea
    # la creacion de la Cotizacion: el correo es un extra, no el paso principal.
    try:
        correo_customer = _correo_de_usuario(db, nueva.usuario_customer_id)
        if correo_customer and SMTP_HOST:
            pdf_bytes = _generar_pdf_cotizacion(db, nueva)
            asunto = f"Nueva Cotización #{nueva.id} asignada"
            cuerpo = (
                f"Estimados, buenas tardes.\n\n"
                f"Se le asignó la Cotización #{nueva.id}. Se adjunta el detalle en PDF.\n\n"
                f"Puede revisarla y confirmarla desde el sistema.\n\n"
                f"Saludos cordiales."
            )
            _enviar_correo(
                db, [correo_customer], asunto, cuerpo, [(f"Cotizacion_{nueva.id}.pdf", pdf_bytes)]
            )
    except Exception:
        pass 

    return nueva


@app.get("/cotizaciones", response_model=List[schemas.CotizacionRead])
def listar_cotizaciones(
    db: Session = Depends(get_db), actor=Depends(requiere("cotizaciones", VER))
):
    """Comercial solo ve las que creó; Customer solo las que le asignaron; el resto ve todas."""
    consulta = db.query(models.Cotizacion)
    rol = _rol_de(db, actor)
    if rol == "COMERCIAL":
        consulta = consulta.filter(models.Cotizacion.usuario_creador_id == actor.id)
    elif rol == "CUSTOMER":
        consulta = consulta.filter(models.Cotizacion.usuario_customer_id == actor.id)
    return consulta.all()


@app.post("/cotizaciones/{cotizacion_id}/jalar", response_model=schemas.RoutingRead)
def jalar_cotizacion(
    cotizacion_id: int,
    db: Session = Depends(get_db),
    actor=Depends(requiere("cotizaciones", JALAR)),
):
    cot = db.query(models.Cotizacion).filter(models.Cotizacion.id == cotizacion_id).first()
    if cot is None:
        raise HTTPException(status_code=404, detail="Cotización no encontrada")
    if not _es_mia_cotizacion(db, actor, cot):
        raise HTTPException(status_code=403, detail="Esta cotización no está asignada a ti")
    if cot.estado != "PENDIENTE":
        raise HTTPException(status_code=400, detail="Esta cotización ya fue jalada")

    total = db.query(models.Routing).filter(models.Routing.numero_routing.isnot(None)).count()
    numero = str(total + 1).zfill(6)

    nuevo_routing = models.Routing(
        cotizacion_id=cot.id,
        numero_routing=numero,
        compania_cliente_id=cot.compania_cliente_id,
        agente_id=cot.agente_id,
        incoterm_id=cot.incoterm_id,
        puerto_origen_id=cot.puerto_origen_id,
        usuario_creador_id=cot.usuario_creador_id,
        usuario_customer_id=cot.usuario_customer_id,
        iva_porcentaje=_iva_vigente(db),
    )
    db.add(nuevo_routing)
    db.commit()
    db.refresh(nuevo_routing)

    valores_cot = db.query(models.CotizacionValores).filter(
        models.CotizacionValores.cotizacion_id == cot.id
    ).all()
    for v in valores_cot:
        db.add(models.RoutingValores(
            routing_id=nuevo_routing.id,
            rubro_id=v.rubro_id,
            compra=v.compra,
            venta=v.venta,
            aplica_iva=v.aplica_iva,
            incluir_en_bl_hijo=v.incluir_en_bl_hijo,
        ))

    cot.estado = "JALADA"
    db.commit()
    db.refresh(nuevo_routing)
    return nuevo_routing


@app.put("/cotizaciones/{cotizacion_id}", response_model=schemas.CotizacionRead)
def editar_cotizacion(
    cotizacion_id: int,
    datos: schemas.CotizacionUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("cotizaciones", EDITAR)),
):
    cot = db.query(models.Cotizacion).filter(models.Cotizacion.id == cotizacion_id).first()
    if cot is None:
        raise HTTPException(status_code=404, detail="Cotización no encontrada")
    if not _es_mia_cotizacion(db, actor, cot):
        raise HTTPException(status_code=403, detail="Esta cotización no es tuya")
    if cot.estado != "PENDIENTE":
        raise HTTPException(status_code=400, detail="Solo se pueden editar cotizaciones PENDIENTES")

    cambios = datos.model_dump(exclude_unset=True, exclude={"valores"})
    for campo, valor in cambios.items():
        if valor is not None:
            setattr(cot, campo, valor)

    if datos.valores is not None:
        db.query(models.CotizacionValores).filter(
            models.CotizacionValores.cotizacion_id == cot.id
        ).delete()
        for valor in datos.valores:
            db.add(models.CotizacionValores(cotizacion_id=cot.id, **valor.model_dump()))

    db.commit()
    db.refresh(cot)
    return cot


@app.delete("/cotizaciones/{cotizacion_id}")
def eliminar_cotizacion(
    cotizacion_id: int, db: Session = Depends(get_db), actor=Depends(requiere("cotizaciones", ELIMINAR))
):
    cot = db.query(models.Cotizacion).filter(models.Cotizacion.id == cotizacion_id).first()
    if cot is None:
        raise HTTPException(status_code=404, detail="Cotización no encontrada")
    if not _es_mia_cotizacion(db, actor, cot):
        raise HTTPException(status_code=403, detail="Esta cotización no es tuya")
    if cot.estado != "PENDIENTE":
        raise HTTPException(status_code=400, detail="Solo se pueden eliminar cotizaciones PENDIENTES")

    db.query(models.CotizacionValores).filter(
        models.CotizacionValores.cotizacion_id == cot.id
    ).delete()
    db.delete(cot)
    db.commit()
    return {"eliminado": True}



# ---------------- ROUTING ----------------

def _es_mio_routing(db: Session, usuario: models.Usuarios, routing: models.Routing) -> bool:
    rol = _rol_de(db, usuario)
    if rol in ("ADMINISTRADOR", "OPERACIONES"):
        return True
    if rol == "COMERCIAL":
        return routing.usuario_creador_id == usuario.id
    if rol == "CUSTOMER":
        return routing.usuario_customer_id == usuario.id
    return False


@app.get("/routing", response_model=List[schemas.RoutingRead])
def listar_routing(db: Session = Depends(get_db), actor=Depends(requiere("routing", VER))):
    consulta = db.query(models.Routing)
    rol = _rol_de(db, actor)
    if rol == "COMERCIAL":
        consulta = consulta.filter(models.Routing.usuario_creador_id == actor.id)
    elif rol == "CUSTOMER":
        consulta = consulta.filter(models.Routing.usuario_customer_id == actor.id)
    return consulta.all()


@app.get("/routing/{routing_id}", response_model=schemas.RoutingRead)
def obtener_routing(
    routing_id: int, db: Session = Depends(get_db), actor=Depends(requiere("routing", VER))
):
    routing = db.query(models.Routing).filter(models.Routing.id == routing_id).first()
    if routing is None:
        raise HTTPException(status_code=404, detail="Routing no encontrado")
    if not _es_mio_routing(db, actor, routing):
        raise HTTPException(status_code=403, detail="Este Routing no es tuyo")
    return routing


def _generar_pdf_routing(db: Session, routing: models.Routing) -> bytes:
    """Arma un PDF de una pagina con el detalle del Routing (para el correo a la Customer)."""
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(20, 60, 120)
    pdf.cell(0, 10, f"ROUTING {routing.numero_routing or ''}", ln=True)
    pdf.set_draw_color(20, 60, 120)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    filas = [
        ("Cliente", _nombre(db, "Companias", routing.compania_cliente_id)),
        ("Agente", _nombre(db, "Companias", routing.agente_id)),
        ("Incoterm", _nombre(db, "Incoterms", routing.incoterm_id)),
        ("Consignatario", _nombre(db, "Companias", routing.consignee_id)),
        ("Notificado", _nombre(db, "Companias", routing.notify_id)),
        ("Puerto de origen", _nombre(db, "Puertos", routing.puerto_origen_id)),
        ("Puerto de destino", _nombre(db, "Puertos", routing.puerto_destino_id)),
        ("Estado", routing.estado),
    ]
    pdf.set_text_color(0, 0, 0)
    for etiqueta, valor in filas:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(50, 8, f"{etiqueta}:")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, str(valor) if valor else "-", ln=True)

    valores = db.query(models.RoutingValores).filter(
        models.RoutingValores.routing_id == routing.id
    ).all()
    if valores:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(20, 60, 120)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(100, 8, "Rubro", border=1, fill=True)
        pdf.cell(40, 8, "Venta", border=1, fill=True, align="R")
        pdf.cell(40, 8, "IVA", border=1, fill=True, align="R", ln=True)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 11)
        iva_pct = routing.iva_porcentaje if routing.iva_porcentaje is not None else _iva_vigente(db)
        subtotal = 0.0
        iva_total = 0.0
        for v in valores:
            venta = v.venta or 0.0
            iva = round(venta * iva_pct / 100, 2) if v.aplica_iva else 0.0
            subtotal += venta
            iva_total += iva
            pdf.cell(100, 8, _nombre(db, "Rubros", v.rubro_id) or "-", border=1)
            pdf.cell(40, 8, f"{venta:.2f}", border=1, align="R")
            pdf.cell(40, 8, f"{iva:.2f}", border=1, align="R", ln=True)

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(140, 8, "TOTAL", border=1, align="R")
        pdf.cell(40, 8, f"{subtotal + iva_total:.2f}", border=1, align="R", ln=True)

    return bytes(pdf.output())


@app.put("/routing/{routing_id}/completar", response_model=schemas.RoutingRead)
def completar_routing(
    routing_id: int,
    datos: schemas.RoutingCompletar,
    db: Session = Depends(get_db),
    actor=Depends(requiere("routing", EDITAR)),
):
    routing = db.query(models.Routing).filter(models.Routing.id == routing_id).first()
    if routing is None:
        raise HTTPException(status_code=404, detail="Routing no encontrado")
    if not _es_mio_routing(db, actor, routing):
        raise HTTPException(status_code=403, detail="Este Routing no es tuyo")
    if routing.estado != "PENDIENTE_CUSTOMER":
        raise HTTPException(status_code=400, detail="Este Routing ya fue completado")

    routing.consignee_id = datos.consignee_id
    routing.notify_id = datos.notify_id
    routing.puerto_destino_id = datos.puerto_destino_id
    routing.estado = "COMPLETADO"

    db.commit()
    db.refresh(routing)

    # Correo a la Customer con el PDF adjunto. Si falla o no hay SMTP configurado,
    # NO se bloquea la respuesta: el Routing ya quedo completado de todas formas.
    try:
        correo_customer = _correo_customer(db, routing)
        if correo_customer and SMTP_HOST:
            pdf_bytes = _generar_pdf_routing(db, routing)
            asunto = f"Routing {routing.numero_routing} completado"
            cuerpo = (
                f"Estimados, buenas tardes.\n\n"
                f"Se completo el Routing {routing.numero_routing}. Se adjunta el detalle en PDF.\n\n"
                f"Saludos cordiales."
            )
            _enviar_correo(
                db, [correo_customer], asunto, cuerpo, [(f"Routing_{routing.numero_routing}.pdf", pdf_bytes)]
            )
    except Exception:
        pass

    return routing


@app.put("/routing/{routing_id}", response_model=schemas.RoutingRead)
def editar_routing(
    routing_id: int,
    datos: schemas.RoutingUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("routing", EDITAR)),
):
    routing = db.query(models.Routing).filter(models.Routing.id == routing_id).first()
    if routing is None:
        raise HTTPException(status_code=404, detail="Routing no encontrado")
    if not _es_mio_routing(db, actor, routing):
        raise HTTPException(status_code=403, detail="Este Routing no es tuyo")

    cambios = datos.model_dump(exclude_unset=True)
    for campo, valor in cambios.items():
        if valor is not None:
            setattr(routing, campo, valor)

    db.commit()
    db.refresh(routing)
    return routing


@app.delete("/routing/{routing_id}")
def eliminar_routing(
    routing_id: int, db: Session = Depends(get_db), actor=Depends(requiere("routing", ELIMINAR))
):
    routing = db.query(models.Routing).filter(models.Routing.id == routing_id).first()
    if routing is None:
        raise HTTPException(status_code=404, detail="Routing no encontrado")
    if not _es_mio_routing(db, actor, routing):
        raise HTTPException(status_code=403, detail="Este Routing no es tuyo")

    db.query(models.RoutingValores).filter(models.RoutingValores.routing_id == routing.id).delete()
    db.delete(routing)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="No se puede eliminar: este Routing ya tiene BL Hijo asociados.",
        )
    return {"eliminado": True}


# ---------------- ITINERARIO ----------------

@app.post("/itinerario", response_model=schemas.ItinerarioRead)
def crear_itinerario(
    itinerario: schemas.ItinerarioCreate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("itinerario", CREAR)),
):
    datos = itinerario.model_dump()
    if datos["anio_operacion"] is None:
        datos["anio_operacion"] = date.today().year

    nuevo = models.Itinerario(**datos)
    db.add(nuevo)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Revisa que el buque, la línea, el puerto y la aduana existan",
        )
    db.refresh(nuevo)
    return nuevo


@app.get("/itinerario", response_model=List[schemas.ItinerarioRead])
def listar_itinerarios(
    db: Session = Depends(get_db), actor=Depends(requiere("itinerario", VER))
):
    return db.query(models.Itinerario).order_by(models.Itinerario.id.desc()).all()


@app.get("/itinerario/{itinerario_id}", response_model=schemas.ItinerarioRead)
def obtener_itinerario(
    itinerario_id: int, db: Session = Depends(get_db), actor=Depends(requiere("itinerario", VER))
):
    itinerario = db.query(models.Itinerario).filter(models.Itinerario.id == itinerario_id).first()
    if itinerario is None:
        raise HTTPException(status_code=404, detail="Itinerario no encontrado")
    return itinerario


@app.put("/itinerario/{itinerario_id}", response_model=schemas.ItinerarioRead)
def editar_itinerario(
    itinerario_id: int,
    datos: schemas.ItinerarioUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("itinerario", EDITAR)),
):
    itinerario = db.query(models.Itinerario).filter(models.Itinerario.id == itinerario_id).first()
    if itinerario is None:
        raise HTTPException(status_code=404, detail="Itinerario no encontrado")

    cambios = datos.model_dump(exclude_unset=True)
    for campo, valor in cambios.items():
        if valor is not None:
            setattr(itinerario, campo, valor)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400, detail="Revisa que el buque, la línea, el puerto y la aduana existan"
        )
    db.refresh(itinerario)
    return itinerario


@app.delete("/itinerario/{itinerario_id}")
def eliminar_itinerario(
    itinerario_id: int, db: Session = Depends(get_db), actor=Depends(requiere("itinerario", ELIMINAR))
):
    itinerario = db.query(models.Itinerario).filter(models.Itinerario.id == itinerario_id).first()
    if itinerario is None:
        raise HTTPException(status_code=404, detail="Itinerario no encontrado")

    try:
        db.delete(itinerario)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400, detail="No se puede eliminar: este itinerario ya tiene BL Master asociados."
        )
    return {"eliminado": True}


# ---------------- BL MASTER ----------------

@app.post("/bl-master", response_model=schemas.BlMasterRead)
def crear_bl_master(
    bl: schemas.BlMasterCreate, db: Session = Depends(get_db), actor=Depends(requiere("bl", CREAR))
):
    itinerario = db.query(models.Itinerario).filter(models.Itinerario.id == bl.itinerario_id).first()
    if itinerario is None:
        raise HTTPException(status_code=404, detail="Itinerario no encontrado")

    repetido = db.query(models.BlMaster).filter(
        models.BlMaster.codigo_bl_master == bl.codigo_bl_master
    ).first()
    if repetido is not None:
        raise HTTPException(status_code=400, detail="Ya existe un BL Master con ese código")

    datos = bl.model_dump()
    if datos["linea_id"] is None:
        datos["linea_id"] = itinerario.linea_id

    nuevo = models.BlMaster(**datos, secuencial="0001", estado="ACTIVO")
    db.add(nuevo)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Revisa que la línea, la naviera, el almacén y el puerto existan",
        )
    db.refresh(nuevo)
    return nuevo


@app.get("/bl-master", response_model=List[schemas.BlMasterRead])
def listar_bl_master(db: Session = Depends(get_db), actor=Depends(requiere("bl", VER))):
    return db.query(models.BlMaster).order_by(models.BlMaster.id.desc()).all()


@app.get("/bl-master/{bl_master_id}", response_model=schemas.BlMasterRead)
def obtener_bl_master(
    bl_master_id: int, db: Session = Depends(get_db), actor=Depends(requiere("bl", VER))
):
    bl = db.query(models.BlMaster).filter(models.BlMaster.id == bl_master_id).first()
    if bl is None:
        raise HTTPException(status_code=404, detail="BL Master no encontrado")
    return bl


@app.put("/bl-master/{bl_master_id}", response_model=schemas.BlMasterRead)
def editar_bl_master(
    bl_master_id: int,
    datos: schemas.BlMasterUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("bl", EDITAR)),
):
    bl = db.query(models.BlMaster).filter(models.BlMaster.id == bl_master_id).first()
    if bl is None:
        raise HTTPException(status_code=404, detail="BL Master no encontrado")

    cambios = datos.model_dump(exclude_unset=True)
    for campo, valor in cambios.items():
        if valor is not None:
            setattr(bl, campo, valor)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Ya existe un BL Master con ese código, o algún dato referenciado no existe")
    db.refresh(bl)
    return bl


@app.delete("/bl-master/{bl_master_id}")
def eliminar_bl_master(
    bl_master_id: int, db: Session = Depends(get_db), actor=Depends(requiere("bl", ELIMINAR))
):
    bl = db.query(models.BlMaster).filter(models.BlMaster.id == bl_master_id).first()
    if bl is None:
        raise HTTPException(status_code=404, detail="BL Master no encontrado")

    try:
        db.delete(bl)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="No se puede eliminar: este BL Master ya tiene BL Hijo asociados.")
    return {"eliminado": True}


# ---------------- BL HIJO ----------------

@app.post("/bl-hijo", response_model=schemas.BlHijoRead)
def crear_bl_hijo(
    bl: schemas.BlHijoCreateConContenedores,
    db: Session = Depends(get_db),
    actor=Depends(requiere("bl", CREAR)),
):
    master = db.query(models.BlMaster).filter(models.BlMaster.id == bl.bl_master_id).first()
    if master is None:
        raise HTTPException(status_code=404, detail="BL Master no encontrado")

    itinerario = db.query(models.Itinerario).filter(
        models.Itinerario.id == master.itinerario_id
    ).first()

    routing = None
    if bl.routing_id is not None:
        routing = db.query(models.Routing).filter(models.Routing.id == bl.routing_id).first()
        if routing is None:
            raise HTTPException(status_code=404, detail="Routing no encontrado")

    repetido = db.query(models.BlHijo).filter(models.BlHijo.codigo_bl == bl.codigo_bl).first()
    if repetido is not None:
        raise HTTPException(status_code=400, detail="Ya existe un BL Hijo con ese código")

    datos = bl.model_dump(exclude={"contenedores"})

    def heredar(campo, valor):
        if datos[campo] is None:
            datos[campo] = valor

    datos["itinerario_id"] = master.itinerario_id
    heredar("linea_id", master.linea_id)
    heredar("naviera_id", master.naviera_id)
    heredar("puerto_embarque_id", master.puerto_embarque_id)
    heredar("fecha_embarque", master.fecha_embarque)
    heredar("almacen_id", master.almacen_id)

    if itinerario is not None:
        heredar("puerto_destino_id", itinerario.puerto_arribo_id)
        heredar("eta", itinerario.fecha_llegada)

    if routing is not None:
        heredar("agente_id", routing.agente_id)
        heredar("consignatario_id", routing.consignee_id or routing.compania_cliente_id)
        heredar("notificado1_id", routing.notify_id)
        heredar("origen_id", routing.puerto_origen_id)

    secuenciales = db.query(models.BlHijo.secuencial).filter(
        models.BlHijo.bl_master_id == master.id
    ).all()
    mayor = max((int(s) for (s,) in secuenciales if s and s.isdigit()), default=0)
    secuencial = str(mayor + 1).zfill(4)

    nuevo = models.BlHijo(**datos, secuencial=secuencial, estado="ASIGNADO")
    db.add(nuevo)
    db.flush()  # para tener nuevo.id y poder crear los contenedores ligados a el

    for item in bl.contenedores:
        db.add(models.Contenedores(**item.model_dump(), bl_hijo_id=nuevo.id))
    db.flush()

    bultos, peso, volumen = _totales_del_master(db, master.id)
    error = _error_si_excede(master, bultos, peso, volumen)
    if error is not None:
        db.rollback()
        raise HTTPException(status_code=400, detail=error)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Revisa que las compañías, puertos, línea, naviera, almacén, moneda y pago existan",
        )
    db.refresh(nuevo)

    # Correo a la Customer + Operaciones con el PDF del BL Hijo. Es un extra: si falla
    # o no hay SMTP configurado, el BL Hijo ya quedo guardado de todas formas.
    try:
        destinatarios = _correos_operaciones(db)
        correo_customer = _correo_customer(db, routing) if routing is not None else None
        if correo_customer:
            destinatarios.add(correo_customer)
        if destinatarios and SMTP_HOST:
            pdf_bytes = _generar_pdf_bl_hijo(db, nuevo)
            asunto = f"BL Hijo {nuevo.codigo_bl} generado"
            cuerpo = (
                f"Estimados, buenas tardes.\n\n"
                f"Se generó el BL Hijo {nuevo.codigo_bl}. Se adjunta el documento en PDF.\n\n"
                f"Saludos cordiales."
            )
            _enviar_correo(
                db, sorted(destinatarios), asunto, cuerpo, [(f"BL_{nuevo.codigo_bl}.pdf", pdf_bytes)]
            )
    except Exception:
        pass

    return nuevo


@app.get("/bl-hijo", response_model=List[schemas.BlHijoRead])
def listar_bl_hijo(db: Session = Depends(get_db), actor=Depends(requiere("bl", VER))):
    return db.query(models.BlHijo).order_by(models.BlHijo.id.desc()).all()


@app.get("/bl-hijo/{bl_hijo_id}", response_model=schemas.BlHijoRead)
def obtener_bl_hijo(
    bl_hijo_id: int, db: Session = Depends(get_db), actor=Depends(requiere("bl", VER))
):
    bl = db.query(models.BlHijo).filter(models.BlHijo.id == bl_hijo_id).first()
    if bl is None:
        raise HTTPException(status_code=404, detail="BL Hijo no encontrado")
    return bl


@app.put("/bl-hijo/{bl_hijo_id}", response_model=schemas.BlHijoRead)
def editar_bl_hijo(
    bl_hijo_id: int,
    datos: schemas.BlHijoUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("bl", EDITAR)),
):
    hijo = db.query(models.BlHijo).filter(models.BlHijo.id == bl_hijo_id).first()
    if hijo is None:
        raise HTTPException(status_code=404, detail="BL Hijo no encontrado")

    cambios = datos.model_dump(exclude_unset=True)
    for campo, valor in cambios.items():
        if valor is not None:
            setattr(hijo, campo, valor)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Ya existe un BL Hijo con ese código, o algún dato referenciado no existe")
    db.refresh(hijo)
    return hijo


@app.delete("/bl-hijo/{bl_hijo_id}")
def eliminar_bl_hijo(
    bl_hijo_id: int, db: Session = Depends(get_db), actor=Depends(requiere("bl", ELIMINAR))
):
    hijo = db.query(models.BlHijo).filter(models.BlHijo.id == bl_hijo_id).first()
    if hijo is None:
        raise HTTPException(status_code=404, detail="BL Hijo no encontrado")

    db.query(models.Contenedores).filter(models.Contenedores.bl_hijo_id == hijo.id).delete()
    db.delete(hijo)
    db.commit()
    return {"eliminado": True}


# ---------------- CONTENEDORES (y totales Master vs Hijos) ----------------

TOLERANCIA = 0.001


def _totales_del_master(db: Session, master_id: int):
    fila = (
        db.query(
            func.coalesce(func.sum(models.Contenedores.no_bultos), 0),
            func.coalesce(func.sum(models.Contenedores.peso_kg), 0.0),
            func.coalesce(func.sum(models.Contenedores.volumen_m3), 0.0),
        )
        .join(models.BlHijo, models.BlHijo.id == models.Contenedores.bl_hijo_id)
        .filter(models.BlHijo.bl_master_id == master_id)
        .one()
    )
    return int(fila[0]), float(fila[1]), float(fila[2])


def _error_si_excede(master, bultos: int, peso: float, volumen: float) -> Optional[str]:
    if (master.bultos or 0) > 0 and bultos > master.bultos:
        return f"Los bultos de los BL Hijo ({bultos}) superan a los del BL Master ({master.bultos})"
    if (master.peso or 0) > 0 and peso > master.peso + TOLERANCIA:
        return f"El peso de los BL Hijo ({peso}) supera al del BL Master ({master.peso})"
    if (master.volumen or 0) > 0 and volumen > master.volumen + TOLERANCIA:
        return f"El volumen de los BL Hijo ({volumen}) supera al del BL Master ({master.volumen})"
    return None


def _advertencia(master, bultos: int, peso: float, volumen: float) -> Optional[str]:
    partes = []
    if bultos != (master.bultos or 0):
        partes.append(f"bultos: Master {master.bultos or 0} vs Hijos {bultos}")
    if abs(peso - (master.peso or 0)) > TOLERANCIA:
        partes.append(f"peso: Master {master.peso or 0} vs Hijos {peso}")
    if abs(volumen - (master.volumen or 0)) > TOLERANCIA:
        partes.append(f"volumen: Master {master.volumen or 0} vs Hijos {volumen}")
    if partes:
        return "Los totales no cuadran - " + "; ".join(partes)
    return None


@app.post("/bl-hijo/{bl_hijo_id}/contenedores", response_model=schemas.ContenedorRead)
def agregar_contenedor(
    bl_hijo_id: int,
    contenedor: schemas.ContenedorCreate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("bl", CREAR)),
):
    hijo = db.query(models.BlHijo).filter(models.BlHijo.id == bl_hijo_id).first()
    if hijo is None:
        raise HTTPException(status_code=404, detail="BL Hijo no encontrado")
    master = db.query(models.BlMaster).filter(models.BlMaster.id == hijo.bl_master_id).first()

    nuevo = models.Contenedores(**contenedor.model_dump(), bl_hijo_id=hijo.id)

    try:
        db.add(nuevo)
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Revisa que el tipo de contenedor, equipamiento, condición, tipo de carga, "
            "embalaje y peligro existan",
        )

    bultos, peso, volumen = _totales_del_master(db, master.id)
    error = _error_si_excede(master, bultos, peso, volumen)
    if error is not None:
        db.rollback()
        raise HTTPException(status_code=400, detail=error)

    db.commit()
    db.refresh(nuevo)
    return nuevo


@app.get("/bl-hijo/{bl_hijo_id}/contenedores", response_model=List[schemas.ContenedorRead])
def listar_contenedores(
    bl_hijo_id: int, db: Session = Depends(get_db), actor=Depends(requiere("bl", VER))
):
    return (
        db.query(models.Contenedores)
        .filter(models.Contenedores.bl_hijo_id == bl_hijo_id)
        .order_by(models.Contenedores.id)
        .all()
    )


@app.put("/contenedores/{contenedor_id}", response_model=schemas.ContenedorRead)
def editar_contenedor(
    contenedor_id: int,
    datos: schemas.ContenedorUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("bl", EDITAR)),
):
    contenedor = db.query(models.Contenedores).filter(models.Contenedores.id == contenedor_id).first()
    if contenedor is None:
        raise HTTPException(status_code=404, detail="Contenedor no encontrado")

    cambios = datos.model_dump(exclude_unset=True)
    for campo, valor in cambios.items():
        if valor is not None:
            setattr(contenedor, campo, valor)

    hijo = db.query(models.BlHijo).filter(models.BlHijo.id == contenedor.bl_hijo_id).first()
    master = db.query(models.BlMaster).filter(models.BlMaster.id == hijo.bl_master_id).first()
    bultos, peso, volumen = _totales_del_master(db, master.id)
    error = _error_si_excede(master, bultos, peso, volumen)
    if error is not None:
        db.rollback()
        raise HTTPException(status_code=400, detail=error)

    db.commit()
    db.refresh(contenedor)
    return contenedor


@app.delete("/contenedores/{contenedor_id}")
def eliminar_contenedor(
    contenedor_id: int, db: Session = Depends(get_db), actor=Depends(requiere("bl", ELIMINAR))
):
    contenedor = db.query(models.Contenedores).filter(models.Contenedores.id == contenedor_id).first()
    if contenedor is None:
        raise HTTPException(status_code=404, detail="Contenedor no encontrado")
    db.delete(contenedor)
    db.commit()
    return {"eliminado": True}


@app.get("/bl-hijo/{bl_hijo_id}/totales", response_model=schemas.TotalesHijoRead)
def totales_del_bl_hijo(
    bl_hijo_id: int, db: Session = Depends(get_db), actor=Depends(requiere("bl", VER))
):
    hijo = db.query(models.BlHijo).filter(models.BlHijo.id == bl_hijo_id).first()
    if hijo is None:
        raise HTTPException(status_code=404, detail="BL Hijo no encontrado")

    fila = (
        db.query(
            func.count(models.Contenedores.id),
            func.coalesce(func.sum(models.Contenedores.no_bultos), 0),
            func.coalesce(func.sum(models.Contenedores.peso_kg), 0.0),
            func.coalesce(func.sum(models.Contenedores.volumen_m3), 0.0),
        )
        .filter(models.Contenedores.bl_hijo_id == bl_hijo_id)
        .one()
    )
    return {
        "total_contenedores": int(fila[0]),
        "total_paquetes": int(fila[1]),
        "total_kilos": float(fila[2]),
        "total_volumen": float(fila[3]),
    }


@app.get("/bl-master/{bl_master_id}/totales", response_model=schemas.TotalesMasterRead)
def totales_del_bl_master(
    bl_master_id: int, db: Session = Depends(get_db), actor=Depends(requiere("bl", VER))
):
    master = db.query(models.BlMaster).filter(models.BlMaster.id == bl_master_id).first()
    if master is None:
        raise HTTPException(status_code=404, detail="BL Master no encontrado")

    bultos, peso, volumen = _totales_del_master(db, master.id)
    return {
        "bultos_master": master.bultos or 0,
        "peso_master": master.peso or 0,
        "volumen_master": master.volumen or 0,
        "bultos_hijos": bultos,
        "peso_hijos": peso,
        "volumen_hijos": volumen,
        "advertencia": _advertencia(master, bultos, peso, volumen),
    }


# ---------------- AVISO DE LLEGADA ----------------

def _puede_ver_aviso(db: Session, usuario: models.Usuarios, hijo: models.BlHijo) -> bool:
    rol = _rol_de(db, usuario)
    if rol in ("ADMINISTRADOR", "OPERACIONES"):
        return True
    if rol == "CUSTOMER" and hijo.routing_id is not None:
        routing = db.query(models.Routing).filter(models.Routing.id == hijo.routing_id).first()
        return routing is not None and routing.usuario_customer_id == usuario.id
    return False


def _correos_operaciones(db: Session):
    """Correo de cada usuario activo con rol OPERACIONES (para el aviso)."""
    filas = (
        db.query(models.Trabajadores.correo)
        .join(models.Usuarios, models.Usuarios.trabajador_id == models.Trabajadores.id)
        .join(models.Roles, models.Roles.id == models.Usuarios.rol_id)
        .filter(models.Roles.nombre == "OPERACIONES", models.Usuarios.activo.is_(True))
        .all()
    )
    return {correo for (correo,) in filas if correo}


def _correo_customer(db: Session, routing):
    """Correo del trabajador ligado al usuario Customer del Routing (o None)."""
    if routing is None or routing.usuario_customer_id is None:
        return None
    customer = db.query(models.Usuarios).filter(
        models.Usuarios.id == routing.usuario_customer_id
    ).first()
    if customer is None:
        return None
    trabajador = db.query(models.Trabajadores).filter(
        models.Trabajadores.id == customer.trabajador_id
    ).first()
    return trabajador.correo if trabajador is not None else None


def _redactar_aviso(aviso: dict):
    """Arma el asunto y el cuerpo del correo, con el formato que ya usan hoy."""
    asunto = f"AVISO DE LLEGADA - BL {aviso['bl_hijo']} - {aviso['buque'] or ''} {aviso['viaje'] or ''}".strip()
    cuerpo = "\n".join([
        "Estimados, buenas tardes.",
        "",
        "Notar el aviso de llegada de la siguiente carga:",
        "",
        f"BL Hijo: {aviso['bl_hijo']}",
        f"BL Master: {aviso['bl_master']}",
        f"MRN: {aviso['mrn']}",
        f"Buque / viaje: {aviso['buque']} {aviso['viaje']}",
        f"Fecha de llegada: {aviso['fecha_llegada']}",
        f"Puerto de arribo: {aviso['puerto_arribo']}",
        f"Almacén: {aviso['almacen']}",
        "",
        "Quedamos atentos a cualquier novedad.",
        "Saludos cordiales.",
    ])
    return asunto, cuerpo


def _enviar_correo(db: Session, destinatarios, asunto: str, cuerpo: str, adjuntos: list = None):
    """Manda el correo de verdad, usando la configuracion guardada en la base de datos
    (con respaldo en el .env si algo todavia no esta configurado ahi)."""
    smtp_host = _config_obtener(db, "SMTP_HOST")
    if not smtp_host:
        raise HTTPException(
            status_code=400,
            detail="El envío por correo no está configurado (falta SMTP_HOST). Configúralo en "
            "PUT /configuracion/SMTP_HOST, o usa /marcar-notificado si ya lo enviaste por otro medio.",
        )
    smtp_port = int(_config_obtener(db, "SMTP_PORT", "587"))
    smtp_user = _config_obtener(db, "SMTP_USER")
    smtp_password = _config_obtener(db, "SMTP_PASSWORD")
    smtp_from = _config_obtener(db, "SMTP_FROM", smtp_user)

    mensaje = EmailMessage()
    mensaje["Subject"] = asunto
    mensaje["From"] = smtp_from or ""
    mensaje["To"] = ", ".join(destinatarios)
    mensaje.set_content(cuerpo)

    for nombre, contenido in (adjuntos or []):
        mensaje.add_attachment(contenido, maintype="application", subtype="pdf", filename=nombre)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as servidor:
            servidor.starttls()
            if smtp_user:
                servidor.login(smtp_user, smtp_password or "")
            servidor.send_message(mensaje)
    except (smtplib.SMTPException, OSError) as error:
        raise HTTPException(status_code=502, detail=f"No se pudo enviar el correo: {error}")


def _armar_aviso(db: Session, hijo: models.BlHijo) -> dict:
    """Junta todos los datos del aviso (lo que ya tenías) + destinatarios y el correo redactado."""
    master = db.query(models.BlMaster).filter(models.BlMaster.id == hijo.bl_master_id).first()
    itinerario = db.query(models.Itinerario).filter(models.Itinerario.id == hijo.itinerario_id).first()
    routing = None
    if hijo.routing_id is not None:
        routing = db.query(models.Routing).filter(models.Routing.id == hijo.routing_id).first()

    iva_pct = _iva_vigente(db)
    if routing is not None and routing.iva_porcentaje is not None:
        iva_pct = routing.iva_porcentaje

    rubros = []
    subtotal = 0.0
    iva_total = 0.0
    if routing is not None:
        valores = db.query(models.RoutingValores).filter(
            models.RoutingValores.routing_id == routing.id
        ).all()
        for v in valores:
            venta = v.venta or 0.0
            iva = round(venta * iva_pct / 100, 2) if v.aplica_iva else 0.0
            subtotal += venta
            iva_total += iva
            rubros.append({
                "rubro": _nombre(db, "Rubros", v.rubro_id),
                "venta": venta,
                "aplica_iva": bool(v.aplica_iva),
                "iva": iva,
            })

    filas = db.query(models.Contenedores).filter(
        models.Contenedores.bl_hijo_id == hijo.id
    ).order_by(models.Contenedores.id).all()
    contenedores = [
        {
            "numero": c.numero_contenedor,
            "sellos": [s for s in (c.sello1, c.sello2, c.sello3, c.sello4) if s],
            "bultos": c.no_bultos or 0,
            "peso_kg": c.peso_kg or 0.0,
            "volumen_m3": c.volumen_m3 or 0.0,
            "descripcion": c.descripcion,
        }
        for c in filas
    ]

    destinatarios = _correos_operaciones(db)
    correo_customer = _correo_customer(db, routing)
    if correo_customer:
        destinatarios.add(correo_customer)

    aviso = {
        "bl_hijo_id": hijo.id,
        "estado": hijo.estado,
        "routing": routing.numero_routing if routing is not None else None,
        "mrn": itinerario.mrn if itinerario is not None else None,
        "bl_master": master.codigo_bl_master if master is not None else None,
        "secuencial_master": master.secuencial if master is not None else None,
        "bl_hijo": hijo.codigo_bl,
        "secuencial_hijo": hijo.secuencial,
        "buque": _nombre(db, "Buques", itinerario.buque_id) if itinerario is not None else None,
        "viaje": itinerario.viaje if itinerario is not None else None,
        "fecha_llegada": itinerario.fecha_llegada if itinerario is not None else None,
        "puerto_arribo": _nombre(db, "Puertos", hijo.puerto_destino_id),
        "almacen": _nombre(db, "Almacenes", hijo.almacen_id),
        "consignatario": _nombre(db, "Companias", hijo.consignatario_id),
        "descripcion": hijo.descripcion_bienes,
        "contenedores": contenedores,
        "rubros": rubros,
        "iva_porcentaje": iva_pct,
        "subtotal": round(subtotal, 2),
        "iva": round(iva_total, 2),
        "total": round(subtotal + iva_total, 2),
        "destinatarios": sorted(destinatarios),
    }
    aviso["asunto"], aviso["cuerpo"] = _redactar_aviso(aviso)
    return aviso


def _generar_pdf_bl_hijo(db: Session, hijo: models.BlHijo) -> bytes:
    """PDF de una pagina con el detalle del BL Hijo (documento de transporte)."""
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(20, 60, 120)
    pdf.cell(0, 10, f"BL {hijo.codigo_bl}", ln=True)
    pdf.set_draw_color(20, 60, 120)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    filas = [
        ("Secuencial", hijo.secuencial),
        ("Embarcador", _nombre(db, "Companias", hijo.embarcador_id)),
        ("Consignatario", _nombre(db, "Companias", hijo.consignatario_id)),
        ("Notificado", _nombre(db, "Companias", hijo.notificado1_id)),
        ("Origen", _nombre(db, "Puertos", hijo.origen_id)),
        ("Puerto de embarque", _nombre(db, "Puertos", hijo.puerto_embarque_id)),
        ("Puerto de destino", _nombre(db, "Puertos", hijo.puerto_destino_id)),
        ("Fecha de embarque", hijo.fecha_embarque),
        ("ETA", hijo.eta),
        ("Marcas y números", hijo.marcas_numeros),
        ("Descripción", hijo.descripcion_bienes),
        ("Instrucciones", hijo.instrucciones_handling),
    ]
    pdf.set_text_color(0, 0, 0)
    for etiqueta, valor in filas:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(50, 8, f"{etiqueta}:")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, str(valor) if valor else "-", ln=True)

    contenedores = db.query(models.Contenedores).filter(
        models.Contenedores.bl_hijo_id == hijo.id
    ).order_by(models.Contenedores.id).all()
    if contenedores:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(20, 60, 120)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(50, 8, "Contenedor", border=1, fill=True)
        pdf.cell(30, 8, "Bultos", border=1, fill=True, align="R")
        pdf.cell(30, 8, "Peso Kg", border=1, fill=True, align="R")
        pdf.cell(30, 8, "Vol m3", border=1, fill=True, align="R", ln=True)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 11)
        for c in contenedores:
            pdf.cell(50, 8, c.numero_contenedor or "-", border=1)
            pdf.cell(30, 8, f"{c.no_bultos or 0}", border=1, align="R")
            pdf.cell(30, 8, f"{c.peso_kg or 0:.2f}", border=1, align="R")
            pdf.cell(30, 8, f"{c.volumen_m3 or 0:.2f}", border=1, align="R", ln=True)

    return bytes(pdf.output())


def _generar_pdf_aviso(aviso: dict) -> bytes:
    """Arma un PDF de una pagina con todo el detalle del Aviso de Llegada."""
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(20, 60, 120)
    pdf.cell(0, 10, f"AVISO DE LLEGADA - BL {aviso['bl_hijo']}", ln=True)
    pdf.set_draw_color(20, 60, 120)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    filas = [
        ("Routing", aviso["routing"]),
        ("MRN", aviso["mrn"]),
        ("BL Master", aviso["bl_master"]),
        ("BL Hijo", aviso["bl_hijo"]),
        ("Buque", aviso["buque"]),
        ("Viaje", aviso["viaje"]),
        ("Fecha de llegada", aviso["fecha_llegada"]),
        ("Puerto de arribo", aviso["puerto_arribo"]),
        ("Almacén", aviso["almacen"]),
        ("Consignatario", aviso["consignatario"]),
        ("Descripción", aviso["descripcion"]),
    ]
    pdf.set_text_color(0, 0, 0)
    for etiqueta, valor in filas:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(50, 8, f"{etiqueta}:")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, str(valor) if valor else "-", ln=True)

    if aviso["contenedores"]:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(20, 60, 120)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(50, 8, "Contenedor", border=1, fill=True)
        pdf.cell(30, 8, "Bultos", border=1, fill=True, align="R")
        pdf.cell(30, 8, "Peso Kg", border=1, fill=True, align="R")
        pdf.cell(30, 8, "Vol m3", border=1, fill=True, align="R", ln=True)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 11)
        for c in aviso["contenedores"]:
            pdf.cell(50, 8, c["numero"] or "-", border=1)
            pdf.cell(30, 8, f"{c['bultos']}", border=1, align="R")
            pdf.cell(30, 8, f"{c['peso_kg']:.2f}", border=1, align="R")
            pdf.cell(30, 8, f"{c['volumen_m3']:.2f}", border=1, align="R", ln=True)

    if aviso["rubros"]:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(20, 60, 120)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(100, 8, "Rubro", border=1, fill=True)
        pdf.cell(40, 8, "Venta", border=1, fill=True, align="R")
        pdf.cell(40, 8, "IVA", border=1, fill=True, align="R", ln=True)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 11)
        for r in aviso["rubros"]:
            pdf.cell(100, 8, r["rubro"] or "-", border=1)
            pdf.cell(40, 8, f"{r['venta']:.2f}", border=1, align="R")
            pdf.cell(40, 8, f"{r['iva']:.2f}", border=1, align="R", ln=True)

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(140, 8, "TOTAL", border=1, align="R")
        pdf.cell(40, 8, f"{aviso['total']:.2f}", border=1, align="R", ln=True)

    return bytes(pdf.output())


@app.get("/aviso-llegada/buscar", response_model=List[schemas.AvisoBusquedaRead])
def buscar_carga(
    q: str, db: Session = Depends(get_db), actor=Depends(requiere("aviso", VER))
):
    patron = f"%{q.strip()}%"
    consulta = (
        db.query(models.BlHijo)
        .outerjoin(models.BlMaster, models.BlMaster.id == models.BlHijo.bl_master_id)
        .outerjoin(models.Routing, models.Routing.id == models.BlHijo.routing_id)
        .filter(
            or_(
                models.BlHijo.codigo_bl.ilike(patron),
                models.BlMaster.codigo_bl_master.ilike(patron),
                models.Routing.numero_routing.ilike(patron),
            )
        )
        .order_by(models.BlHijo.id.desc())
    )

    rol = _rol_de(db, actor)
    if rol == "CUSTOMER":
        consulta = consulta.filter(models.Routing.usuario_customer_id == actor.id)

    resultado = []
    for hijo in consulta.all():
        master = db.query(models.BlMaster).filter(models.BlMaster.id == hijo.bl_master_id).first()
        routing = None
        if hijo.routing_id is not None:
            routing = db.query(models.Routing).filter(models.Routing.id == hijo.routing_id).first()
        resultado.append({
            "bl_hijo_id": hijo.id,
            "bl_hijo": hijo.codigo_bl,
            "bl_master": master.codigo_bl_master if master is not None else None,
            "routing": routing.numero_routing if routing is not None else None,
            "estado": hijo.estado,
        })
    return resultado


@app.get("/aviso-llegada/{bl_hijo_id}", response_model=schemas.AvisoRead)
def ver_aviso_de_llegada(
    bl_hijo_id: int, db: Session = Depends(get_db), actor=Depends(requiere("aviso", VER))
):
    hijo = db.query(models.BlHijo).filter(models.BlHijo.id == bl_hijo_id).first()
    if hijo is None:
        raise HTTPException(status_code=404, detail="BL Hijo no encontrado")
    if not _puede_ver_aviso(db, actor, hijo):
        raise HTTPException(status_code=403, detail="Esta carga no está asignada a ti")
    return _armar_aviso(db, hijo)


@app.post("/aviso-llegada/{bl_hijo_id}/marcar-notificado")
def marcar_notificado(
    bl_hijo_id: int, db: Session = Depends(get_db), actor=Depends(requiere("aviso", NOTIFICAR))
):
    """Para cuando el aviso se envió por otro medio (impreso, WhatsApp, etc.)."""
    hijo = db.query(models.BlHijo).filter(models.BlHijo.id == bl_hijo_id).first()
    if hijo is None:
        raise HTTPException(status_code=404, detail="BL Hijo no encontrado")
    if not _puede_ver_aviso(db, actor, hijo):
        raise HTTPException(status_code=403, detail="Esta carga no está asignada a ti")

    hijo.estado = "NOTIFICADO"
    db.commit()
    db.refresh(hijo)
    return {"bl_hijo_id": hijo.id, "estado": hijo.estado}


@app.post("/aviso-llegada/{bl_hijo_id}/enviar")
def enviar_por_correo(
    bl_hijo_id: int, db: Session = Depends(get_db), actor=Depends(requiere("aviso", NOTIFICAR))
):
    hijo = db.query(models.BlHijo).filter(models.BlHijo.id == bl_hijo_id).first()
    if hijo is None:
        raise HTTPException(status_code=404, detail="BL Hijo no encontrado")
    if not _puede_ver_aviso(db, actor, hijo):
        raise HTTPException(status_code=403, detail="Esta carga no está asignada a ti")

    aviso = _armar_aviso(db, hijo)
    if not aviso["destinatarios"]:
        raise HTTPException(
            status_code=400,
            detail="No hay destinatarios: falta el correo de la Customer o de los usuarios de OPERACIONES.",
        )

    adjuntos = [
        (f"Aviso_{aviso['bl_hijo']}.pdf", _generar_pdf_aviso(aviso)),
        (f"BL_{hijo.codigo_bl}.pdf", _generar_pdf_bl_hijo(db, hijo)),
    ]
    _enviar_correo(db, aviso["destinatarios"], aviso["asunto"], aviso["cuerpo"], adjuntos)

    hijo.estado = "NOTIFICADO"
    db.commit()
    db.refresh(hijo)
    return {"enviado": True, "destinatarios": aviso["destinatarios"], "estado": hijo.estado}


# ---------------- ROLES ----------------

@app.post("/roles", response_model=schemas.RolRead)
def crear_rol(
    rol: schemas.RolCreate, db: Session = Depends(get_db), actor=Depends(requiere("seguridad", CREAR))
):
    nombre = rol.nombre.strip().upper()
    repetido = db.query(models.Roles).filter(models.Roles.nombre == nombre).first()
    if repetido is not None:
        raise HTTPException(status_code=400, detail="Ya existe un rol con ese nombre")

    nuevo = models.Roles(nombre=nombre)
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return nuevo


@app.get("/roles", response_model=List[schemas.RolRead])
def listar_roles(db: Session = Depends(get_db), actor=Depends(requiere("seguridad", VER))):
    return db.query(models.Roles).order_by(models.Roles.id).all()


# ---------------- CATEGORÍAS DE TRABAJADOR ----------------

@app.post("/categorias", response_model=schemas.CategoriaRead)
def crear_categoria(
    categoria: schemas.CategoriaCreate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("seguridad", CREAR)),
):
    nombre = categoria.nombre.strip().upper()
    repetida = db.query(models.CategoriasTrabajador).filter(
        models.CategoriasTrabajador.nombre == nombre
    ).first()
    if repetida is not None:
        raise HTTPException(status_code=400, detail="Ya existe una categoría con ese nombre")

    nueva = models.CategoriasTrabajador(nombre=nombre)
    db.add(nueva)
    db.commit()
    db.refresh(nueva)
    return nueva


@app.get("/categorias", response_model=List[schemas.CategoriaRead])
def listar_categorias(db: Session = Depends(get_db), actor=Depends(requiere("seguridad", VER))):
    return db.query(models.CategoriasTrabajador).order_by(models.CategoriasTrabajador.nombre).all()


# ---------------- TRABAJADORES ----------------

def _con_categorias(db: Session, trabajador):
    ids = [
        fila.categoria_id
        for fila in db.query(models.TrabajadorCategoria).filter(
            models.TrabajadorCategoria.trabajador_id == trabajador.id
        )
    ]
    if ids:
        trabajador.categorias = (
            db.query(models.CategoriasTrabajador)
            .filter(models.CategoriasTrabajador.id.in_(ids))
            .order_by(models.CategoriasTrabajador.nombre)
            .all()
        )
    else:
        trabajador.categorias = []
    return trabajador


@app.post("/trabajadores", response_model=schemas.TrabajadorRead)
def crear_trabajador(
    datos: schemas.TrabajadorCreate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("seguridad", CREAR)),
):
    nombre = datos.nombre.strip().upper()
    correo = datos.correo.strip().lower()

    if "@" not in correo:
        raise HTTPException(status_code=400, detail="El correo no es válido")
    repetido = db.query(models.Trabajadores).filter(models.Trabajadores.correo == correo).first()
    if repetido is not None:
        raise HTTPException(status_code=400, detail="Ya existe un trabajador con ese correo")

    categorias_ids = set(datos.categorias_ids)
    if categorias_ids:
        existentes = {
            c.id
            for c in db.query(models.CategoriasTrabajador).filter(
                models.CategoriasTrabajador.id.in_(categorias_ids)
            )
        }
        faltantes = categorias_ids - existentes
        if faltantes:
            raise HTTPException(
                status_code=400, detail=f"Estas categorías no existen: {sorted(faltantes)}"
            )

    nuevo = models.Trabajadores(nombre=nombre, correo=correo)
    db.add(nuevo)
    db.flush()

    for categoria_id in categorias_ids:
        db.add(models.TrabajadorCategoria(trabajador_id=nuevo.id, categoria_id=categoria_id))

    db.commit()
    db.refresh(nuevo)
    return _con_categorias(db, nuevo)


@app.get("/trabajadores", response_model=List[schemas.TrabajadorRead])
def listar_trabajadores(
    categoria_id: Optional[int] = None,
    db: Session = Depends(get_db),
    actor=Depends(requiere("seguridad", VER)),
):
    consulta = db.query(models.Trabajadores)
    if categoria_id is not None:
        consulta = consulta.join(
            models.TrabajadorCategoria,
            models.TrabajadorCategoria.trabajador_id == models.Trabajadores.id,
        ).filter(models.TrabajadorCategoria.categoria_id == categoria_id)

    trabajadores = consulta.order_by(models.Trabajadores.nombre).all()
    return [_con_categorias(db, t) for t in trabajadores]


@app.get("/trabajadores/{trabajador_id}", response_model=schemas.TrabajadorRead)
def obtener_trabajador(
    trabajador_id: int, db: Session = Depends(get_db), actor=Depends(requiere("seguridad", VER))
):
    trabajador = db.query(models.Trabajadores).filter(
        models.Trabajadores.id == trabajador_id
    ).first()
    if trabajador is None:
        raise HTTPException(status_code=404, detail="Trabajador no encontrado")
    return _con_categorias(db, trabajador)


# ---------------- USUARIOS ----------------

def _con_nombres(db: Session, usuario):
    usuario.rol = _nombre(db, "Roles", usuario.rol_id)
    usuario.trabajador = _nombre(db, "Trabajadores", usuario.trabajador_id)
    return usuario


@app.post("/usuarios", response_model=schemas.UsuarioRead)
def crear_usuario(
    datos: schemas.UsuarioCreate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("seguridad", CREAR)),
):
    nombre_usuario = datos.usuario.strip().lower()

    trabajador = db.query(models.Trabajadores).filter(
        models.Trabajadores.id == datos.trabajador_id
    ).first()
    if trabajador is None:
        raise HTTPException(status_code=404, detail="Trabajador no encontrado")

    rol = db.query(models.Roles).filter(models.Roles.id == datos.rol_id).first()
    if rol is None:
        raise HTTPException(status_code=404, detail="Rol no encontrado")

    repetido = db.query(models.Usuarios).filter(models.Usuarios.usuario == nombre_usuario).first()
    if repetido is not None:
        raise HTTPException(status_code=400, detail="Ese nombre de usuario ya existe")

    ya_tiene = db.query(models.Usuarios).filter(
        models.Usuarios.trabajador_id == trabajador.id
    ).first()
    if ya_tiene is not None:
        raise HTTPException(status_code=400, detail="Este trabajador ya tiene un usuario")

    nuevo = models.Usuarios(
        trabajador_id=trabajador.id,
        rol_id=rol.id,
        usuario=nombre_usuario,
        password_hash=_hash_password(datos.password),
        activo=datos.activo,
    )
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return _con_nombres(db, nuevo)


@app.get("/usuarios", response_model=List[schemas.UsuarioRead])
def listar_usuarios(db: Session = Depends(get_db), actor=Depends(requiere("seguridad", VER))):
    usuarios = db.query(models.Usuarios).order_by(models.Usuarios.usuario).all()
    return [_con_nombres(db, u) for u in usuarios]


@app.get("/usuarios/{usuario_id}", response_model=schemas.UsuarioRead)
def obtener_usuario(
    usuario_id: int, db: Session = Depends(get_db), actor=Depends(requiere("seguridad", VER))
):
    usuario = db.query(models.Usuarios).filter(models.Usuarios.id == usuario_id).first()
    if usuario is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return _con_nombres(db, usuario)


@app.put("/usuarios/{usuario_id}", response_model=schemas.UsuarioRead)
def editar_usuario(
    usuario_id: int,
    datos: schemas.UsuarioUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("seguridad", EDITAR)),
):
    usuario = db.query(models.Usuarios).filter(models.Usuarios.id == usuario_id).first()
    if usuario is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if datos.rol_id is not None:
        rol = db.query(models.Roles).filter(models.Roles.id == datos.rol_id).first()
        if rol is None:
            raise HTTPException(status_code=404, detail="Rol no encontrado")
        usuario.rol_id = datos.rol_id

    if datos.activo is not None:
        if usuario.id == actor.id and datos.activo is False:
            raise HTTPException(status_code=400, detail="No puedes desactivar tu propio usuario")
        usuario.activo = datos.activo

    if datos.password is not None:
        usuario.password_hash = _hash_password(datos.password)

    db.commit()
    db.refresh(usuario)
    return _con_nombres(db, usuario)


@app.delete("/usuarios/{usuario_id}")
def eliminar_usuario(
    usuario_id: int, db: Session = Depends(get_db), actor=Depends(requiere("seguridad", ELIMINAR))
):
    usuario = db.query(models.Usuarios).filter(models.Usuarios.id == usuario_id).first()
    if usuario is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if usuario.id == actor.id:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propio usuario")

    db.delete(usuario)
    db.commit()
    return {"eliminado": True}


# ---------------- MAESTROS (catálogos genéricos) ----------------

def _obtener_modelo_maestro(tabla: str):
    if tabla not in models.MAESTROS_SIMPLES:
        raise HTTPException(status_code=404, detail=f"El maestro '{tabla}' no existe")
    nombre_clase = tabla.title().replace("_", "")
    return getattr(models, nombre_clase)


@app.post("/maestros/{tabla}", response_model=schemas.MaestroRead)
def crear_maestro(
    tabla: str,
    maestro: schemas.MaestroCreate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("maestros", CREAR)),
):
    Modelo = _obtener_modelo_maestro(tabla)
    nuevo = Modelo(**maestro.model_dump())
    db.add(nuevo)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Ya existe un registro con ese código")
    db.refresh(nuevo)
    return nuevo


@app.get("/maestros/{tabla}", response_model=List[schemas.MaestroRead])
def listar_maestro(
    tabla: str, db: Session = Depends(get_db), actor=Depends(requiere("maestros", VER))
):
    Modelo = _obtener_modelo_maestro(tabla)
    return db.query(Modelo).all()


@app.put("/maestros/{tabla}/{registro_id}", response_model=schemas.MaestroRead)
def editar_maestro(
    tabla: str,
    registro_id: int,
    datos: schemas.MaestroUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("maestros", EDITAR)),
):
    Modelo = _obtener_modelo_maestro(tabla)
    fila = db.query(Modelo).filter(Modelo.id == registro_id).first()
    if fila is None:
        raise HTTPException(status_code=404, detail="Registro no encontrado")

    cambios = datos.model_dump(exclude_unset=True)
    for campo, valor in cambios.items():
        if valor is not None:
            setattr(fila, campo, valor)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Ya existe un registro con ese código")
    db.refresh(fila)
    return fila


@app.delete("/maestros/{tabla}/{registro_id}")
def eliminar_maestro(
    tabla: str,
    registro_id: int,
    db: Session = Depends(get_db),
    actor=Depends(requiere("maestros", ELIMINAR)),
):
    Modelo = _obtener_modelo_maestro(tabla)
    fila = db.query(Modelo).filter(Modelo.id == registro_id).first()
    if fila is None:
        raise HTTPException(status_code=404, detail="Registro no encontrado")

    try:
        db.delete(fila)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="No se puede eliminar: este registro ya está en uso. Mejor desactívalo (activo=false).",
        )
    return {"eliminado": True}  


# ---------------- CONFIGURACIÓN (API) ----------------

@app.get("/configuracion", response_model=List[schemas.ConfiguracionRead])
def listar_configuracion(db: Session = Depends(get_db), actor=Depends(requiere("configuracion", VER))):
    """Los valores guardados. Los sensibles (como SMTP_PASSWORD) se muestran ocultos."""
    filas = db.query(models.Configuracion).order_by(models.Configuracion.clave).all()
    return [
        {"clave": f.clave, "valor": "********" if f.clave in CLAVES_SENSIBLES else f.valor}
        for f in filas
    ]


@app.put("/configuracion/{clave}", response_model=schemas.ConfiguracionRead)
def guardar_configuracion(
    clave: str,
    datos: schemas.ConfiguracionUpdate,
    db: Session = Depends(get_db),
    actor=Depends(requiere("configuracion", EDITAR)),
):
    """Crea o actualiza un valor. Ej: PUT /configuracion/IVA_PORCENTAJE {"valor": "15"}"""
    clave = clave.strip().upper()
    fila = _config_guardar(db, clave, datos.valor)
    valor_mostrado = "********" if clave in CLAVES_SENSIBLES else fila.valor
    return {"clave": fila.clave, "valor": valor_mostrado}