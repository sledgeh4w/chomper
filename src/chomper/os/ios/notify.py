class NotifyServer:
    """Handle Darwin notifications."""

    def __init__(self):
        self._states = {}

        self._client_token_registry = {}
        self._name_id_registry = {}

        self._name_id_seed = 1

        self._init_states()

    def _init_states(self):
        # percent | charging << 17 | valid << 19 | external << 21
        self._states["com.apple.system.powersources.percent"] = 100 | (1 << 19)

    def check(self, client_token: int) -> int:
        return 1 if client_token in self._client_token_registry else 0

    def register_check(self, name: str, client_token: int) -> int:
        for key, value in self._name_id_registry.items():
            if value == name:
                name_id = key
                break
        else:
            name_id = self._name_id_seed
            self._name_id_registry[name_id] = name
            self._name_id_seed += 1

        self._client_token_registry[client_token] = name

        return name_id

    def get_state_2(self, name_id: int) -> int:
        name = self._name_id_registry.get(name_id)
        return self._states.get(name, 0)

    def get_state_3(self, client_token: int) -> int:
        name = self._client_token_registry.get(client_token)
        return self._states.get(name, 0)
