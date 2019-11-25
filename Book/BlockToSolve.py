import datetime

class BlockToSolve:
    # Atributos
    _from = None
    to = None
    #  2. Dados a serem guardados no Bloco.
    value = None
    #  4. Hash do objeto deste bloco.
    hash = None
    #  6. Data de criação deste bloco.
    dataDeCriacao = datetime.datetime.now()