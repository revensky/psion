class Scope(str):
    """
    Defines the model of an OAuth 2.1 Scope.

    The scope is a string that defines a name for Authorization Control.

    This class provides an implementation that exposes both the name of the scope
    as well as a description for documentation and consent purposes.

    Directly accessing the instance returns the name of the scope,
    since the description has no use to the OAuth 2.1 Framework.

    :param name: Name of the scope.
    :type name: str

    :param description: Description of the scope.
    :type description: str
    """

    name: str
    description: str

    def __new__(cls, name: str, description: str = None) -> str:
        klass = super().__new__(cls, name)
        klass.name = name
        klass.description = description
        return klass

    def __init__(self, name: str, description: str = None) -> None:
        pass
