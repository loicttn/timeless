import pony.orm as pony

database = pony.Database("sqlite", "debugger.sqlite",
                         create_db=True)


class State(database.Entity):
    """
    defines state save
    """
    registers = pony.Set("Register")
    instruction = pony.Set("Instruction")


class Register(database.Entity):
    """
    defines all registers saves
    """
    name = pony.Required(str)
    reg_id = pony.Required(int)
    value = pony.Optional(pony.Json)
    state = pony.Required(State)


class Instruction(database.Entity):
    """
    defines instruction save
    """
    address = pony.Required(int)
    size = pony.Required(int)
    data = pony.Optional(pony.Json)
    state = pony.Required(State)


def create_db() -> object:
    """
    creates a database

    uses @database to create a database file instance with pony
    according to the defined models
    """
    # pony.sql_debug(True)
    database.generate_mapping(create_tables=True)