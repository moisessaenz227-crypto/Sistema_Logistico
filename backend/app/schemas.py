from datetime import date
from typing import List, Optional

from pydantic import BaseModel, Field


# ---------------- COMPAÑÍAS ----------------

class CompaniaCreate(BaseModel):
    nombre: str
    tipo_identificacion_id: Optional[int] = None
    numero_id: Optional[str] = None
    pais_id: Optional[int] = None
    ciudad_id: Optional[int] = None
    direccion: Optional[str] = None


class CompaniaRead(CompaniaCreate):
    id: int

    class Config:
        from_attributes = True


class CompaniaUpdate(BaseModel):
    nombre: Optional[str] = None
    tipo_identificacion_id: Optional[int] = None
    numero_id: Optional[str] = None
    pais_id: Optional[int] = None
    ciudad_id: Optional[int] = None
    direccion: Optional[str] = None


# ---------------- COTIZACIONES ----------------

class CotizacionValorItem(BaseModel):
    rubro_id: int
    compra: float
    venta: float
    aplica_iva: bool = True
    incluir_en_bl_hijo: bool = False


class CotizacionValorRead(CotizacionValorItem):
    id: int

    class Config:
        from_attributes = True


class CotizacionCreate(BaseModel):
    compania_cliente_id: int
    agente_id: int
    incoterm_id: Optional[int] = None
    shipper_nombre: Optional[str] = None
    pais_origen_id: Optional[int] = None
    ciudad_origen_id: Optional[int] = None
    puerto_origen_id: Optional[int] = None
    usuario_creador_id: Optional[int] = None
    usuario_customer_id: Optional[int] = None
    valores: List[CotizacionValorItem]


class CotizacionRead(BaseModel):
    id: int
    compania_cliente_id: int
    agente_id: int
    incoterm_id: Optional[int]
    shipper_nombre: Optional[str]
    pais_origen_id: Optional[int]
    ciudad_origen_id: Optional[int]
    puerto_origen_id: Optional[int]
    usuario_creador_id: Optional[int]
    usuario_customer_id: Optional[int]
    estado: str
    valores: List[CotizacionValorRead] = []

    class Config:
        from_attributes = True


class CotizacionUpdate(BaseModel):
    compania_cliente_id: Optional[int] = None
    agente_id: Optional[int] = None
    incoterm_id: Optional[int] = None
    shipper_nombre: Optional[str] = None
    pais_origen_id: Optional[int] = None
    ciudad_origen_id: Optional[int] = None
    puerto_origen_id: Optional[int] = None
    usuario_customer_id: Optional[int] = None
    valores: Optional[List[CotizacionValorItem]] = None


# ---------------- ROUTING ----------------

class RoutingValorRead(CotizacionValorItem):
    id: int

    class Config:
        from_attributes = True


class RoutingRead(BaseModel):
    id: int
    cotizacion_id: Optional[int]
    numero_routing: Optional[str]
    compania_cliente_id: Optional[int]
    agente_id: Optional[int]
    incoterm_id: Optional[int]
    puerto_origen_id: Optional[int]
    consignee_id: Optional[int]
    notify_id: Optional[int]
    puerto_destino_id: Optional[int]
    usuario_creador_id: Optional[int]
    usuario_customer_id: Optional[int]
    iva_porcentaje: Optional[float] = None
    estado: str
    valores: List[RoutingValorRead] = []

    class Config:
        from_attributes = True


class RoutingCompletar(BaseModel):
    consignee_id: int
    notify_id: Optional[int] = None
    puerto_destino_id: int


class RoutingUpdate(BaseModel):
    compania_cliente_id: Optional[int] = None
    agente_id: Optional[int] = None
    incoterm_id: Optional[int] = None
    puerto_origen_id: Optional[int] = None
    consignee_id: Optional[int] = None
    notify_id: Optional[int] = None
    puerto_destino_id: Optional[int] = None


# ---------------- MAESTROS (catálogos genéricos) ----------------

class MaestroCreate(BaseModel):
    codigo: Optional[str] = None
    nombre: str
    activo: bool = True
    codigo_aduana: Optional[str] = None


class MaestroRead(MaestroCreate):
    id: int

    class Config:
        from_attributes = True


class MaestroUpdate(BaseModel):
    codigo: Optional[str] = None
    nombre: Optional[str] = None
    activo: Optional[bool] = None
    codigo_aduana: Optional[str] = None
    

# ---------------- ITINERARIO ----------------

class ItinerarioCreate(BaseModel):
    buque_id: int
    viaje: str
    linea_id: Optional[int] = None
    puerto_arribo_id: Optional[int] = None
    fecha_llegada: Optional[date] = None
    mrn: Optional[str] = None
    aduana_id: Optional[int] = None
    anio_operacion: Optional[int] = None
    manifiesto: Optional[str] = None


class ItinerarioRead(ItinerarioCreate):
    id: int

    class Config:
        from_attributes = True


class ItinerarioUpdate(BaseModel):
    buque_id: Optional[int] = None
    viaje: Optional[str] = None
    linea_id: Optional[int] = None
    puerto_arribo_id: Optional[int] = None
    fecha_llegada: Optional[date] = None
    mrn: Optional[str] = None
    aduana_id: Optional[int] = None
    anio_operacion: Optional[int] = None
    manifiesto: Optional[str] = None


# ---------------- BL MASTER ----------------

class BlMasterCreate(BaseModel):
    itinerario_id: int
    codigo_bl_master: str
    linea_id: Optional[int] = None
    naviera_id: Optional[int] = None
    almacen_id: Optional[int] = None
    puerto_embarque_id: Optional[int] = None
    fecha_embarque: Optional[date] = None
    bultos: int = 0
    peso: float = 0
    volumen: float = 0


class BlMasterRead(BlMasterCreate):
    id: int
    secuencial: Optional[str] = None
    estado: Optional[str] = None

    class Config:
        from_attributes = True


class TotalesMasterRead(BaseModel):
    bultos_master: int
    peso_master: float
    volumen_master: float
    bultos_hijos: int
    peso_hijos: float
    volumen_hijos: float
    advertencia: Optional[str] = None


class BlMasterUpdate(BaseModel):
    codigo_bl_master: Optional[str] = None
    secuencial: Optional[str] = None
    linea_id: Optional[int] = None
    naviera_id: Optional[int] = None
    almacen_id: Optional[int] = None
    puerto_embarque_id: Optional[int] = None
    fecha_embarque: Optional[date] = None
    bultos: Optional[int] = None
    peso: Optional[float] = None
    volumen: Optional[float] = None


# ---------------- BL HIJO ----------------

class BlHijoCreate(BaseModel):
    bl_master_id: int
    codigo_bl: str
    descripcion_bienes: str
    routing_id: Optional[int] = None
    marcas_numeros: Optional[str] = None
    instrucciones_handling: str = "N/A"
    origen_id: Optional[int] = None
    embarcador_id: Optional[int] = None
    consignatario_id: Optional[int] = None
    notificado1_id: Optional[int] = None
    notificado2_id: Optional[int] = None
    # Estos se autocompletan si no se envían (desde BL Master, Itinerario y Routing):
    agente_id: Optional[int] = None
    linea_id: Optional[int] = None
    naviera_id: Optional[int] = None
    puerto_embarque_id: Optional[int] = None
    fecha_embarque: Optional[date] = None
    almacen_id: Optional[int] = None
    puerto_destino_id: Optional[int] = None
    eta: Optional[date] = None
    coloading: bool = False
    bl_guia_primario: Optional[str] = None
    valor_a_declarar: Optional[float] = None
    moneda_flete_id: Optional[int] = None
    pago_flete_id: Optional[int] = None


class BlHijoRead(BlHijoCreate):
    id: int
    itinerario_id: Optional[int] = None
    secuencial: Optional[str] = None
    estado: Optional[str] = None

    class Config:
        from_attributes = True


class BlHijoUpdate(BaseModel):
    codigo_bl: Optional[str] = None
    routing_id: Optional[int] = None
    descripcion_bienes: Optional[str] = None
    marcas_numeros: Optional[str] = None
    instrucciones_handling: Optional[str] = None
    origen_id: Optional[int] = None
    embarcador_id: Optional[int] = None
    consignatario_id: Optional[int] = None
    notificado1_id: Optional[int] = None
    notificado2_id: Optional[int] = None
    agente_id: Optional[int] = None
    linea_id: Optional[int] = None
    naviera_id: Optional[int] = None
    puerto_embarque_id: Optional[int] = None
    fecha_embarque: Optional[date] = None
    almacen_id: Optional[int] = None
    puerto_destino_id: Optional[int] = None
    eta: Optional[date] = None
    coloading: Optional[bool] = None
    bl_guia_primario: Optional[str] = None
    valor_a_declarar: Optional[float] = None
    moneda_flete_id: Optional[int] = None
    pago_flete_id: Optional[int] = None


class TotalesHijoRead(BaseModel):
    total_paquetes: int
    total_kilos: float
    total_volumen: float
    total_contenedores: int


# ---------------- CONTENEDORES ----------------

class ContenedorCreate(BaseModel):
    numero_contenedor: Optional[str] = None
    sello1: Optional[str] = None
    sello2: Optional[str] = None
    sello3: Optional[str] = None
    sello4: Optional[str] = None
    tipo_contenedor_id: Optional[int] = None
    equipamiento_id: Optional[int] = None
    condicion_id: Optional[int] = None
    no_bultos: int = 0
    peso_kg: float = 0
    volumen_m3: float = 0
    tipo_carga_id: Optional[int] = None
    embalaje_id: Optional[int] = None
    peligro_id: Optional[int] = None
    descripcion: Optional[str] = None
    incluir_en_impresion: bool = True


class ContenedorRead(ContenedorCreate):
    id: int
    bl_hijo_id: int

    class Config:
        from_attributes = True


class ContenedorUpdate(BaseModel):
    numero_contenedor: Optional[str] = None
    sello1: Optional[str] = None
    sello2: Optional[str] = None
    sello3: Optional[str] = None
    sello4: Optional[str] = None
    tipo_contenedor_id: Optional[int] = None
    equipamiento_id: Optional[int] = None
    condicion_id: Optional[int] = None
    no_bultos: Optional[int] = None
    peso_kg: Optional[float] = None
    volumen_m3: Optional[float] = None
    tipo_carga_id: Optional[int] = None
    embalaje_id: Optional[int] = None
    peligro_id: Optional[int] = None
    descripcion: Optional[str] = None
    incluir_en_impresion: Optional[bool] = None


# ---------------- AVISO DE LLEGADA ----------------

class AvisoBusquedaRead(BaseModel):
    bl_hijo_id: int
    bl_hijo: str
    bl_master: Optional[str] = None
    routing: Optional[str] = None
    estado: Optional[str] = None


class AvisoContenedorRead(BaseModel):
    numero: Optional[str] = None
    sellos: List[str] = []
    bultos: int
    peso_kg: float
    volumen_m3: float
    descripcion: Optional[str] = None


class AvisoRubroRead(BaseModel):
    rubro: Optional[str] = None
    venta: float
    aplica_iva: bool
    iva: float


class AvisoRead(BaseModel):
    bl_hijo_id: int
    estado: Optional[str] = None
    routing: Optional[str] = None
    mrn: Optional[str] = None
    bl_master: Optional[str] = None
    secuencial_master: Optional[str] = None
    bl_hijo: str
    secuencial_hijo: Optional[str] = None
    buque: Optional[str] = None
    viaje: Optional[str] = None
    fecha_llegada: Optional[date] = None
    puerto_arribo: Optional[str] = None
    almacen: Optional[str] = None
    consignatario: Optional[str] = None
    descripcion: str
    contenedores: List[AvisoContenedorRead] = []
    rubros: List[AvisoRubroRead] = []
    iva_porcentaje: float
    subtotal: float
    iva: float
    total: float
    destinatarios: List[str] = []
    asunto: str = ""
    cuerpo: str = ""

# ---------------- ROLES ----------------

class RolCreate(BaseModel):
    nombre: str


class RolRead(RolCreate):
    id: int

    class Config:
        from_attributes = True


# ---------------- CATEGORÍAS DE TRABAJADOR ----------------

class CategoriaCreate(BaseModel):
    nombre: str


class CategoriaRead(CategoriaCreate):
    id: int

    class Config:
        from_attributes = True


# ---------------- TRABAJADORES ----------------

class TrabajadorCreate(BaseModel):
    nombre: str
    correo: str
    categorias_ids: List[int] = []


class TrabajadorRead(BaseModel):
    id: int
    nombre: str
    correo: str
    categorias: List[CategoriaRead] = []

    class Config:
        from_attributes = True


# ---------------- USUARIOS ----------------

class UsuarioCreate(BaseModel):
    trabajador_id: int
    rol_id: int
    usuario: str
    password: str = Field(min_length=6)  # mínimo 6 caracteres
    activo: bool = True


class UsuarioRead(BaseModel):
    """OJO: aquí NO existe ningún campo de contraseña: nunca se devuelve, ni siquiera cifrada."""

    id: int
    usuario: str
    activo: Optional[bool] = True
    trabajador_id: Optional[int] = None
    rol_id: Optional[int] = None
    rol: Optional[str] = None
    trabajador: Optional[str] = None

    class Config:
        from_attributes = True


class UsuarioUpdate(BaseModel):
    rol_id: Optional[int] = None
    activo: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=6)


class TokenRead(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UsuarioUpdate(BaseModel):
    rol_id: Optional[int] = None
    activo: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=6)