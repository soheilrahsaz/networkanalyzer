package entity;

public class InterfaceModel {
    private int id;
    private String name;

    public InterfaceModel(int id, String name) {
        this.id = id;
        this.name = name;
    }

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
    }
}
