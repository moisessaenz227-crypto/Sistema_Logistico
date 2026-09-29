from sqlalchemy import Column, Integer, String, Boolean, Float, Date, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class Trabajadores(Base):
    __tablename__ = "trabajadores"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, nullable=False)
    correo = Column(String, nullable=False)


class CategoriasTrabajador(Base):
    __tablename__ = "categorias_trabajador"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, nullable=False)


class TrabajadorCategoria(Base):
    __tablename__ = "trabajador_categoria"

    trabajador_id = Column(Integer, ForeignKey("trabajadores.id"), primary_key=True)
    categoria_id = Column(Integer, ForeignKey("categorias_trabajador.id"), primary_key=True)


class Roles(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, nullable=False)


class Usuarios(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    trabajador_id = Column(Integer, ForeignKey("trabajadores.id"))
    rol_id = Column(Integer, ForeignKey("roles.id"))
    usuario = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    activo = Column(Boolean, default=True)


class Companias(Base):
    __tablename__ = "companias"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, nullable=False)
    tipo_identificacion_id = Column(Integer, ForeignKey("tipos_identificacion.id"))
    numero_id = Column(String)
    pais_id = Column(Integer, ForeignKey("paises.id"))
    ciudad_id = Column(Integer, ForeignKey("ciudades.id"))
    direccion = Column(String)


class CompaniaTipo(Base):
    __tablename__ = "compania_tipo"

    compania_id = Column(Integer, ForeignKey("companias.id"), primary_key=True)
    tipo_compania_id = Column(Integer, ForeignKey("tipos_compania.id"), primary_key=True)


class Cotizacion(Base):
    __tablename__ = "cotizacion"

    id = Column(Integer, primary_key=True, index=True)
    compania_cliente_id = Column(Integer, ForeignKey("companias.id"), nullable=False)
    agente_id = Column(Integer, ForeignKey("companias.id"), nullable=False)
    incoterm_id = Column(Integer, ForeignKey("incoterms.id"))
    shipper_nombre = Column(String)
    pais_origen_id = Column(Integer, ForeignKey("paises.id"))
    ciudad_origen_id = Column(Integer, ForeignKey("ciudades.id"))
    puerto_origen_id = Column(Integer, ForeignKey("puertos.id"))
    usuario_creador_id = Column(Integer, ForeignKey("usuarios.id"))
    usuario_customer_id = Column(Integer, ForeignKey("usuarios.id"))
    estado = Column(String, default="PENDIENTE")


class CotizacionValores(Base):
    __tablename__ = "cotizacion_valores"

    id = Column(Integer, primary_key=True, index=True)
    cotizacion_id = Column(Integer, ForeignKey("cotizacion.id"))
    rubro_id = Column(Integer, ForeignKey("rubros.id"), nullable=False)
    compra = Column(Float, nullable=False)
    venta = Column(Float, nullable=False)
    aplica_iva = Column(Boolean, default=True)
    incluir_en_bl_hijo = Column(Boolean, default=False)


class Routing(Base):
    __tablename__ = "routing"

    id = Column(Integer, primary_key=True, index=True)
    cotizacion_id = Column(Integer, ForeignKey("cotizacion.id"))
    numero_routing = Column(String, unique=True, nullable=True)
    compania_cliente_id = Column(Integer, ForeignKey("companias.id"))
    agente_id = Column(Integer, ForeignKey("companias.id"))
    incoterm_id = Column(Integer, ForeignKey("incoterms.id"))
    puerto_origen_id = Column(Integer, ForeignKey("puertos.id"))
    consignee_id = Column(Integer, ForeignKey("companias.id"))
    notify_id = Column(Integer, ForeignKey("companias.id"))
    puerto_destino_id = Column(Integer, ForeignKey("puertos.id"))
    usuario_creador_id = Column(Integer, ForeignKey("usuarios.id"))
    usuario_customer_id = Column(Integer, ForeignKey("usuarios.id"))
    iva_porcentaje = Column(Float)
    estado = Column(String, default="PENDIENTE_CUSTOMER")


class RoutingValores(Base):
    __tablename__ = "routing_valores"

    id = Column(Integer, primary_key=True, index=True)
    routing_id = Column(Integer, ForeignKey("routing.id"))
    rubro_id = Column(Integer, ForeignKey("rubros.id"))
    compra = Column(Float)
    venta = Column(Float)
    aplica_iva = Column(Boolean, default=True)
    incluir_en_bl_hijo = Column(Boolean, default=False)


class RoutingContenedores(Base):
    __tablename__ = "routing_contenedores"

    id = Column(Integer, primary_key=True, index=True)
    routing_id = Column(Integer, ForeignKey("routing.id"))
    tipo_contenedor_id = Column(Integer, ForeignKey("tipos_contenedor.id"))
    cantidad = Column(Integer)


class Itinerario(Base):
    __tablename__ = "itinerario"

    id = Column(Integer, primary_key=True, index=True)
    buque_id = Column(Integer, ForeignKey("buques.id"))
    linea_id = Column(Integer, ForeignKey("lineas.id"))
    viaje = Column(String)
    puerto_arribo_id = Column(Integer, ForeignKey("puertos.id"))
    fecha_llegada = Column(Date)
    mrn = Column(String)
    aduana_id = Column(Integer, ForeignKey("aduanas.id"))
    anio_operacion = Column(Integer)
    manifiesto = Column(String)


class BlMaster(Base):
    __tablename__ = "bl_master"

    id = Column(Integer, primary_key=True, index=True)
    itinerario_id = Column(Integer, ForeignKey("itinerario.id"))
    codigo_bl_master = Column(String)
    secuencial = Column(String, default="0001")
    linea_id = Column(Integer, ForeignKey("lineas.id"))
    naviera_id = Column(Integer, ForeignKey("navieras.id"))
    almacen_id = Column(Integer, ForeignKey("almacenes.id"))
    puerto_embarque_id = Column(Integer, ForeignKey("puertos.id"))
    fecha_embarque = Column(Date)
    bultos = Column(Integer)
    peso = Column(Float)
    volumen = Column(Float)
    estado = Column(String)


class BlHijo(Base):
    __tablename__ = "bl_hijo"

    id = Column(Integer, primary_key=True, index=True)
    bl_master_id = Column(Integer, ForeignKey("bl_master.id"))
    routing_id = Column(Integer, ForeignKey("routing.id"))
    itinerario_id = Column(Integer, ForeignKey("itinerario.id"))
    codigo_bl = Column(String)
    secuencial = Column(String, default="0001")
    linea_id = Column(Integer, ForeignKey("lineas.id"))
    naviera_id = Column(Integer, ForeignKey("navieras.id"))
    origen_id = Column(Integer, ForeignKey("puertos.id"))
    embarcador_id = Column(Integer, ForeignKey("companias.id"))
    consignatario_id = Column(Integer, ForeignKey("companias.id"))
    notificado1_id = Column(Integer, ForeignKey("companias.id"))
    notificado2_id = Column(Integer, ForeignKey("companias.id"))
    agente_id = Column(Integer, ForeignKey("companias.id"))
    puerto_embarque_id = Column(Integer, ForeignKey("puertos.id"))
    fecha_embarque = Column(Date)
    almacen_id = Column(Integer, ForeignKey("almacenes.id"))
    puerto_destino_id = Column(Integer, ForeignKey("puertos.id"))
    eta = Column(Date)
    coloading = Column(Boolean, default=False)
    bl_guia_primario = Column(String)
    estado = Column(String, default="ASIGNADO")
    marcas_numeros = Column(String)
    descripcion_bienes = Column(String, nullable=False)
    instrucciones_handling = Column(String, default="N/A")
    valor_a_declarar = Column(Float)
    moneda_flete_id = Column(Integer, ForeignKey("monedas.id"))
    pago_flete_id = Column(Integer, ForeignKey("pagos.id"))


class Contenedores(Base):
    __tablename__ = "contenedores"

    id = Column(Integer, primary_key=True, index=True)
    bl_hijo_id = Column(Integer, ForeignKey("bl_hijo.id"))
    numero_contenedor = Column(String)
    sello1 = Column(String)
    sello2 = Column(String)
    sello3 = Column(String)
    sello4 = Column(String)
    tipo_contenedor_id = Column(Integer, ForeignKey("tipos_contenedor.id"))
    equipamiento_id = Column(Integer, ForeignKey("equipamientos.id"))
    condicion_id = Column(Integer, ForeignKey("condiciones.id"))
    no_bultos = Column(Integer)
    peso_kg = Column(Float)
    volumen_m3 = Column(Float)
    tipo_carga_id = Column(Integer, ForeignKey("tipos_carga.id"))
    embalaje_id = Column(Integer, ForeignKey("embalajes.id"))
    peligro_id = Column(Integer, ForeignKey("peligros_imo.id"))
    descripcion = Column(String)
    incluir_en_impresion = Column(Boolean, default=True)


MAESTROS_SIMPLES = [
    "paises", "ciudades", "puertos", "almacenes", "monedas", "incoterms", "aduanas",
    "navieras", "lineas", "buques", "tipos_manifiesto", "tipos_transporte",
    "tipos_contenedor", "equipamientos", "condiciones", "tipos_carga", "embalajes",
    "peligros_imo", "pagos", "tipos_identificacion", "tipos_compania", "rubros",
]


def _make_maestro_class(tabla: str):
    attrs = {
        "__tablename__": tabla,
        "id": Column(Integer, primary_key=True, index=True),
        "codigo": Column(String, unique=True, index=True),
        "nombre": Column(String, nullable=False),
        "activo": Column(Boolean, default=True),
        "codigo_aduana": Column(String),
    }
    return type(tabla.title().replace("_", ""), (Base,), attrs)


for _tabla in MAESTROS_SIMPLES:
    globals()[_tabla.title().replace("_", "")] = _make_maestro_class(_tabla)