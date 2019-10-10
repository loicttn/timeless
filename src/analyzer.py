class Analyzer:
    """
    performs binary analysis
    """
    def __init__(self: object, binary_name, logs: str = None) -> None:
        """
        loads binary and logging infos
        """
        self.binary_name = binary_name
        self.binary_infos = {
            "name": binary_name,
            "magic_number": None,
            "format": None,
            "bits": None,
            "endianness": None,
            "size": None,
            "content": None,
        }
        self.logs = logs

    def _log(self: object, message: str) -> None:
        """
        logs content of message
        """
        if self.logs:
            with open(self.logs, 'w') as f:
                f.write(message)
        else:
            print(f"[*] {message}")

    def get(self: object) -> dict:
        """
        returns binary_infos
        """
        return self.binary_infos

    def run(self: object) -> None:
        """
        performs all binary extraction infos
        """
        with open(self.binary_infos["name"], "rb") as f:
            header = f.read(6)
            self.binary_infos["magic_number"] = header[0]
            self.binary_infos["format"] = f"{chr(header[1])}{chr(header[2])}{chr(header[3])}" 
            self.binary_infos["bits"] = int(header[4]) * 32
            try:
                self.binary_infos["endianness"] = ["little", "big"][(int(header[5]) - 1)]
            except IndexError:
                name = self.binary_infos.get("name")
                self._log(f"Error: {name} is not an ELF binary")
                exit(1)
            self.binary_infos["content"] = f.read()
        self._log("File analysis done")
